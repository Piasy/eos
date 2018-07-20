/**
 *  @file
 *  @copyright defined in eosio/LICENSE.txt
 */

#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <fc/crypto/hex.hpp>
#include <fc/variant.hpp>
#include <fc/io/datastream.hpp>
#include <fc/io/json.hpp>
#include <fc/io/console.hpp>
#include <fc/exception/exception.hpp>
#include <fc/variant_object.hpp>
#include <eosio/utilities/key_conversion.hpp>

#include <eosio/chain/name.hpp>
#include <eosio/chain/config.hpp>
#include <eosio/chain/wast_to_wasm.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/contract_types.hpp>

#pragma push_macro("N")
#undef N

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/process/spawn.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/sort.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <boost/algorithm/string/classification.hpp>

#pragma pop_macro("N")

#include <Inline/BasicTypes.h>
#include <IR/Module.h>
#include <IR/Validate.h>
#include <WAST/WAST.h>
#include <WASM/WASM.h>
#include <Runtime/Runtime.h>

#include <fc/io/fstream.hpp>

#include "CLI11.hpp"
#include "help_text.hpp"
#include "localize.hpp"
#include "config.hpp"
#include "httpc.hpp"

using namespace std;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::utilities;
using namespace eosio::client::help;
using namespace eosio::client::http;
using namespace eosio::client::localize;
using namespace eosio::client::config;
using namespace boost::filesystem;

string url = "http://47.52.72.79:8000/";
string wallet_url = "http://123.56.66.149:6666/";

eosio::client::http::http_context context;
bool no_verify = false;
vector<string> headers;

auto tx_expiration = fc::seconds(30);
string tx_ref_block_num_or_id;
bool tx_force_unique = false;
bool tx_dont_broadcast = false;
bool tx_skip_sign = false;
bool tx_print_json = false;
bool print_request = true;
bool print_response = true;

uint8_t tx_max_cpu_usage = 0;
uint32_t tx_max_net_usage = 0;

template<typename T>
fc::variant call(const std::string &url,
                 const std::string &path,
                 const T &v) {
    try {
        eosio::client::http::connection_param *cp = new eosio::client::http::connection_param(context,
                                                                                              parse_url(url) + path,
                                                                                              no_verify ? false : true,
                                                                                              headers);

        return eosio::client::http::do_http_call(*cp, fc::variant(v), print_request, print_response);
    }
    catch (boost::system::system_error &e) {
        if (url == ::url)
            std::cerr << localized("Failed to connect to nodeos at ${u}; is nodeos running?", ("u", url)) << std::endl;
        else if (url == ::wallet_url)
            std::cerr << localized("Failed to connect to keosd at ${u}; is keosd running?", ("u", url)) << std::endl;
        throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, e.what())});
    }
}

template<typename T>
fc::variant call(const std::string &path,
                 const T &v) { return call(url, path, fc::variant(v)); }

template<>
fc::variant call(const std::string &url,
                 const std::string &path) { return call(url, path, fc::variant()); }

eosio::chain_apis::read_only::get_info_results get_info() {
    return call(url, get_info_func).as<eosio::chain_apis::read_only::get_info_results>();
}

fc::variant determine_required_keys(const signed_transaction &trx) {
    // TODO better error checking
    const auto &public_keys = call(wallet_url, wallet_public_keys);
    auto get_arg = fc::mutable_variant_object
            ("transaction", (transaction) trx)
            ("available_keys", public_keys);
    const auto &required_keys = call(get_required_keys, get_arg);
    return required_keys["required_keys"];
}

void sign_transaction(signed_transaction &trx, fc::variant &required_keys, const chain_id_type &chain_id) {
    fc::variants sign_args = {fc::variant(trx), required_keys, fc::variant(chain_id)};
    const auto &signed_trx = call(wallet_url, wallet_sign_trx, sign_args);
    trx = signed_trx.as<signed_transaction>();
}

chain::action generate_nonce_action() {
    return chain::action({}, config::null_account_name, "nonce",
                         fc::raw::pack(fc::time_point::now().time_since_epoch().count()));
}

fc::variant push_transaction(signed_transaction &trx, int32_t extra_kcpu = 1000,
                             packed_transaction::compression_type compression = packed_transaction::none) {
    auto info = get_info();
    trx.expiration = info.head_block_time + tx_expiration;

    // Set tapos, default to last irreversible block if it's not specified by the user
    block_id_type ref_block_id = info.last_irreversible_block_id;
    try {
        fc::variant ref_block;
        if (!tx_ref_block_num_or_id.empty()) {
            ref_block = call(get_block_func, fc::mutable_variant_object("block_num_or_id", tx_ref_block_num_or_id));
            ref_block_id = ref_block["id"].as<block_id_type>();
        }
    } EOS_RETHROW_EXCEPTIONS(invalid_ref_block_exception, "Invalid reference block num or id: ${block_num_or_id}",
                             ("block_num_or_id", tx_ref_block_num_or_id));
    trx.set_reference_block(ref_block_id);

    if (tx_force_unique) {
        trx.context_free_actions.emplace_back(generate_nonce_action());
    }

    trx.max_cpu_usage_ms = tx_max_cpu_usage;
    trx.max_net_usage_words = (tx_max_net_usage + 7) / 8;

    if (!tx_skip_sign) {
        auto required_keys = determine_required_keys(trx);
        sign_transaction(trx, required_keys, info.chain_id);
    }

    if (!tx_dont_broadcast) {
        return call(push_txn_func, packed_transaction(trx, compression));
    } else {
        return fc::variant(trx);
    }
}

int main(int argc, char **argv) {
    wlog(("crypto-test"));

    setlocale(LC_ALL, "");
    bindtextdomain(locale_domain, locale_path);
    textdomain(locale_domain);
    context = eosio::client::http::create_http_context();

    //auto transfer = fc::mutable_variant_object
    //        ("from", "piasypiasy11")
    //        ("to", "piasypiasy22")
    //        ("quantity", "1.0000 SYS")
    //        ("memo", "memo");
    //
    //auto args = fc::mutable_variant_object
    //        ("code", "eosio.token")
    //        ("action", "transfer")
    //        ("args", transfer);
    //
    //auto result = call(json_to_bin_func, args);

    auto act = action{
            vector < chain::permission_level > {{"piasypiasy11", config::active_name}}, "eosio.token", "transfer",
            fc::variant("1082c7c6558f8dab2084c7c6558f8dab10270000000000000453595300000000046d656d6f").as<bytes>()
    };
    std::vector<chain::action> &&actions = {act};

    signed_transaction trx;
    trx.actions = std::forward<decltype(actions)>({actions});

    trx.expiration = fc::time_point_sec::from_iso_string("2018-07-20T08:31:11");
    trx.ref_block_num = 4667U;
    trx.ref_block_prefix = 2333071186UL;

    trx.max_cpu_usage_ms = tx_max_cpu_usage;
    trx.max_net_usage_words = (tx_max_net_usage + 7) / 8;

    std::vector<std::string> required_keys = {"EOS69X3383RzBZj41k73CSjUNXM5MYGpnDxyPnWUKPEtYQmTBWz4D"};
    fc::variants sign_args = {fc::variant(trx), fc::variant(required_keys),
                              fc::variant("1c6ae7719a2a3b4ecb19584a30ff510ba1b6ded86e1fd8b8fc22f1179c622a32")};

    chain::signed_transaction stxn(sign_args.at(0).as<chain::signed_transaction>());
    flat_set<public_key_type> keys = sign_args.at(1).as<flat_set<public_key_type>>();
    chain::chain_id_type id = sign_args.at(2).as<chain::chain_id_type>();

    digest_type digest = stxn.sig_digest(id, stxn.context_free_data);
    private_key_type priv_key = fc::variant(
            "5JtUScZK2XEp3g9gh7F8bwtPTRAkASmNrrftmx4AxDKD5K4zDnr").as<private_key_type>();
    for (const auto &pk : keys) {
        signature_type sig = priv_key.sign(digest);
        stxn.signatures.push_back(sig);

        wlog("pub key  ${m}", ("m", pk));
        wlog("priv key ${m}", ("m", priv_key));
        wlog("digest   ${m}", ("m", digest));
        wlog("sig      ${m}", ("m", sig));
    }

    auto packed_trx = packed_transaction(stxn, packed_transaction::none);
    auto trx_meta = transaction_metadata(packed_trx);

    //auto recover_key = trx_meta.recover_keys(id);
    auto recover_key = public_key_type(stxn.signatures[0], digest);

    // change digest from
    // 02cbf67609b90498656a6744d6b38997afcf4823ad86dacd37bdae1c4fa0f3ec
    // to
    // 02cbf67609b90498656a6744d6b38997afcf4823ad86dacd37bdae1c4fa0f3ed
    // would not recover public key
    // EOS69X3383RzBZj41k73CSjUNXM5MYGpnDxyPnWUKPEtYQmTBWz4D
    // but
    // EOS8SUWwyfZ81Sa3m9yZZCSVRA79LXw2pN7cKYjFmwritxf6MxkAV
    //auto recover_key = public_key_type(stxn.signatures[0],
    //        fc::variant("02cbf67609b90498656a6744d6b38997afcf4823ad86dacd37bdae1c4fa0f3ed").as<digest_type>());

    // change signature would cause exception
    //auto recover_key = public_key_type(
    //        fc::variant("SIG_K1_Kan3zjxWg2c9gEBMBxxfYXpgfhRtd4zftUgauhFwJRBRq53YnBrJdVKJg7CWeUTwMRBhpUyMZfbii8sWfjvK3oHoiad1PT").as<signature_type>(),
    //        digest);

    wlog("signed transaction ${m}", ("m", stxn));
    wlog("packed transaction ${m}", ("m", packed_trx));
    wlog("transaction meta   ${m}", ("m", trx_meta));
    wlog("recover_key        ${m}", ("m", recover_key));

    return 0;
}
