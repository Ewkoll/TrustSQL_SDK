#include "TrustSQL_SDK.h"
#include "chttp.h"
#include "json/elements.h"
#include "json/reader.h"
#include "json/writer.h"

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#if !defined(min)
#define min(a, b) ((a < b) ? (a) : (b))
#endif

#define CHAR_LOCATE   "GBK"
#define HTTP_PROTOCOL "https"
#define HTTP_HEADERS(headers)                                    \
{                                                                \
    headers["Content-Type"] = "application/json; charset=utf-8"; \
    headers["cache-control"] = "no-cache";                       \
}

// 信息共享服务的mch_pubkey公钥
const static char s_iss_pubkey[PUBKEY_DIGEST_LENGTH] = "BC8s/4qEAvVl4Sv0LwQOWJcVU6Q5hBd+7LlJeEivVmUbdtwP4RTfN8x/G+muMhN8SrweyyVVMIcIrnMWoFqGfIA=";
const static char s_dam_pubkey[PUBKEY_DIGEST_LENGTH] = "BC8s/4qEAvVl4Sv0LwQOWJcVU6Q5hBd+7LlJeEivVmUbdtwP4RTfN8x/G+muMhN8SrweyyVVMIcIrnMWoFqGfIA=";


template<class _Type>
std::string toString(const _Type& t)
{
    std::stringstream ss_t;
    ss_t << t;
    return ss_t.str();
}

json::Array tGeneratePairkey(const size_t count)
{
    json::Array result;
    result.Resize(count);

    for (size_t i = 0; i < count; i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char pubkey[PUBKEY_DIGEST_LENGTH] = { 0 };
        //generate a pair of public key and private key
        if (GeneratePairkey(prvkey, pubkey) == 0) {
            result[i]["private_key"] = std::string(prvkey);
            result[i]["public_key"] = std::string(pubkey);
        }
        else {
            result[i]["error"] = GetErrorStr();
        }
    }

    return result;
}

json::Array tCheckPairkey(const json::Array& params)
{
    json::Array result;
    result.Resize(params.Size() / 2);

    for (size_t i = 0; i < params.Size() / 2; i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char pubkey[PUBKEY_DIGEST_LENGTH] = { 0 };

        std::string s_prvkey = params[i * 2].Pack();
        std::string s_pubkey = params[i * 2 + 1].Pack();

        strncpy(prvkey, s_prvkey.c_str(), min(PRVKEY_DIGEST_LENGTH, s_prvkey.size()));
        strncpy(pubkey, s_pubkey.c_str(), min(PUBKEY_DIGEST_LENGTH, s_pubkey.size()));

        result[i]["private_key"] = s_prvkey;
        result[i]["public_key"] = s_pubkey;
        //check the pair of public key and private key
        switch (CheckPairkey(prvkey, pubkey)) {
        case 0:
            result[i]["verify"] = true;
            break;
        case 1:
            result[i]["verify"] = false;
            break;
        default:
            result[i]["error"] = GetErrorStr();
            break;
        }

    }

    return result;
}

json::Array tGeneratePubkeyByPrvkey(const json::Array& params)
{
    json::Array result;
    result.Resize(params.Size());

    for(size_t i = 0; i < params.Size() ; i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char pubkey[PUBKEY_DIGEST_LENGTH] = { 0 };

        std::string s_prvkey = params[i].Pack();
        strncpy(prvkey, s_prvkey.c_str(), min(PRVKEY_DIGEST_LENGTH, s_prvkey.size()));
        //convert the private key to public key
        if (GeneratePubkeyByPrvkey(prvkey, pubkey) == 0) {
            result[i]["private_key"] = std::string(prvkey);
            result[i]["public_key"] = std::string(pubkey);
        }
        else {
            result[i]["error"] = GetErrorStr();
        }
    }

    return result;
}

json::Array tGenerateAddrByPubkey(const json::Array& params)
{
    json::Array result;
    result.Resize(params.Size());

    for(size_t i = 0; i < params.Size() ; i++) {
        char pubkey[PUBKEY_DIGEST_LENGTH] = { 0 };
        char addr[ADDR_DIGEST_LENGTH] = { 0 };

        std::string s_pubkey = params[i].Pack();
        strncpy(pubkey, s_pubkey.c_str(), min(PUBKEY_DIGEST_LENGTH, s_pubkey.size()));
        //calculate the address by public key
        if (GenerateAddrByPubkey(pubkey, addr) == 0) {
            result[i]["public_key"] = std::string(pubkey);
            result[i]["address"] = std::string(addr);
        }
        else {
            result[i]["error"] = GetErrorStr();
        }
    }

    return result;
}

json::Array tGenerateAddrByPrvkey(const json::Array& params)
{
    json::Array result;
    result.Resize(params.Size());

    for(size_t i = 0; i < params.Size() ; i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char addr[ADDR_DIGEST_LENGTH] = { 0 };

        std::string s_prvkey = params[i].Pack();
        strncpy(prvkey, s_prvkey.c_str(), min(PRVKEY_DIGEST_LENGTH, s_prvkey.size()));
        //calculate the address by private key
        if (GenerateAddrByPrvkey(prvkey, addr) == 0) {
            result[i]["private_key"] = std::string(prvkey);
            result[i]["address"] = std::string(addr);
        }
        else {
            result[i]["error"] = GetErrorStr();
        }
    }

    return result;
}

json::Array tSignString(const char* params1, const char* params2)
{
    json::Array result;

    char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
    char sign[SIGN_DIGEST_LENGTH] = { 0 };

    std::string s_prvkey = params1;
    std::string s_text = params2;
    std::string s_text_hex;

    strncpy(prvkey, s_prvkey.c_str(), min(PRVKEY_DIGEST_LENGTH, s_prvkey.size()));

    char hexTemp[3];
    for (size_t j = 0; j < s_text.size(); j++) {
        sprintf(hexTemp, "%02x", (unsigned char)s_text[j] );
        s_text_hex.append(hexTemp);
    }
    //sign a string with private key
    if (SignString(prvkey, s_text.c_str(), s_text.size(), sign) == 0) {
        result[0]["private_key"] = std::string(prvkey);
        result[0]["text"] = s_text;
        result[0]["text_hex"] = s_text_hex;
        result[0]["sign"] = std::string(sign);
    }
    else {
        result[0]["error"] = GetErrorStr();
    }

    return result;
}

json::Array tVerifySign(const char* params1, const char* params2, const char* params3)
{
    json::Array result;

    char pubkey[PUBKEY_DIGEST_LENGTH] = { 0 };
    char sign[SIGN_DIGEST_LENGTH] = { 0 };

    std::string s_pubkey = params1;
    std::string s_text = params2;
    std::string s_sign = params3;
    std::string s_text_hex;

    strncpy(pubkey, s_pubkey.c_str(), min(PUBKEY_DIGEST_LENGTH, s_pubkey.size()));
    strncpy(sign, s_sign.c_str(), min(SIGN_DIGEST_LENGTH, s_sign.size()));

    char hexTemp[3];
    for (size_t j = 0; j < s_text.size(); j++) {
        sprintf(hexTemp, "%02x", (unsigned char)s_text[j]);
        s_text_hex.append(hexTemp);
    }

    result[0]["public_key"] = std::string(pubkey);
    result[0]["text"] = s_text;
    result[0]["text_hex"] = s_text_hex;
    result[0]["sign"] = std::string(sign);
    //verify a sign with pubkey key
    switch (VerifySign(pubkey, s_text.c_str(), s_text.size(), sign)) {
    case 0:
        result[0]["verify"] = true;
        break;
    case 1:
        result[0]["verify"] = false;
        break;
    default:
        result[0]["error"] = GetErrorStr();
        break;
    }

    return result;
}


struct args_options
{
    args_options()
    {
        domain = "baas.qq.com";
        proxy = "";
        verbose = false;
    }

    void parse(int argc, char **argv)
    {
        int32_t opt;
        static struct option long_options[] = {
            { "domain",  required_argument, 0, 'd' },
            { "proxy",   required_argument, 0, 'p' },
            { "verbose", no_argument,       0, 'v' },
            { 0,         0,                 0,  0 }
        };

        while ((opt = getopt_long(argc, argv, "d:p:v", long_options, 0)) != -1) {
            switch (opt) {
            case 'd':
                domain = strdup(optarg);
                break;
            case 'p':
                proxy = strdup(optarg);
                break;
            case 'v':
                verbose = true;
                break;
            default:
                break;
            }
        }
    }

    std::string domain;
    std::string proxy;
    bool verbose;
};


json::Array tIssAppend(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 节点ID       node_id
    // 链ID         chain_id
    // 账本ID       ledger_id
    // 信息标识		info_key
    // 信息版本号	info_version
    // 状态			state
    // 信息内容		content
    // 线索内容		notes
    // 信息更新时间	commit_time
    // 记录方地址	account
    // 记录方公钥	public_key
    // 记录方签名	sign

    for (size_t i = 0; i < params.Size(); i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char pubkey[PUBKEY_DIGEST_LENGTH] = { 0 };
        char addr[ADDR_DIGEST_LENGTH] = { 0 };
        char sign[SIGN_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["version"] = params[i]["version"].Pack();
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        json::Object obj_param = params[i];
        if (obj_param.Find("node_id") != obj_param.End()) {
            mpsig["node_id"] = obj_param["node_id"].Pack();
        }
        mpsig["chain_id"] = params[i]["chain_id"].Pack();
        mpsig["ledger_id"] = params[i]["ledger_id"].Pack();
        mpsig["info_key"] = params[i]["info_key"].Pack();
        mpsig["info_version"] = params[i]["info_version"].Pack();
        mpsig["state"] = params[i]["state"].Pack();
        mpsig["content"] = params[i]["content"].Pack();
        mpsig["notes"] = params[i]["notes"].Pack();
        mpsig["commit_time"] = params[i]["commit_time"].Pack();
		mpsig["timestamp"] = toString(time(0));

        std::string private_key = params[i]["private_key"].Pack();
        strncpy(prvkey, private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, private_key.size()));

        // 得到地址account 补全到参数列表
        if (GenerateAddrByPrvkey(prvkey, addr) == 0) {
            mpsig["account"] = std::string(addr);
            fprintf(stdout, "account=%s\n", addr);

            fprintf(stdout, "addr=%s\n", addr);
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // 得到公钥public_key 补全到参数列表
        if (GeneratePubkeyByPrvkey(prvkey, pubkey) == 0) {
            mpsig["public_key"] = std::string(pubkey);
            fprintf(stdout, "pubkey=%s\n", pubkey);
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        std::string sign_str = params[i]["sign"].Pack();
        if (sign_str == "") {
            mpsig["sign"] = "";
        } else {
            if (SignRenString(prvkey, sign_str.c_str(), sign_str.size(), sign) == 0) {
                mpsig["sign"] = std::string(sign);

            } else {
                result[0]["error"] = GetErrorStr();
            }
        }


        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "content" || it->first == "notes") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/trustsql_iss_append_v1.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_iss_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }

#if 0
            // 验证返回数据的sign
            switch (IssVerifySign(
                jo_result["info_key"].Pack().c_str(),
                atoi(jo_result["info_version"].Pack().c_str()),
                atoi(jo_result["state"].Pack().c_str()),
                jo_result["content"].Pack().c_str(),
                jo_result["notes"].Pack().c_str(),
                jo_result["commit_time"].Pack().c_str(),
                pubkey,
                jo_result["sign"].Pack().c_str())) {
            case 0:
                jo_result["sign_verify"] = true;
                break;
            case 1:
                jo_result["sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
#endif
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tIssQuery(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());
    
    // 接口版本	    version
    // 签名方式	    sign_type
    // 通讯方ID	    mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 信息标识	    info_key
    // 信息版本号	info_version
    // 状态	        state
    // 信息内容	    content
    // 线索内容	    notes
    // 范围查询条件	range
    // 记录方地址	account
    // 记录哈希	    t_hash
    // 页码	        page_no
    // 每页数量	    page_limit
    // 请求时间	    timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];
        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "content" || it->first == "notes" || it->first == "range") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/trustsql_iss_query_v1.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_iss_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }

#if 0
            // 验证返回的每个共享信息的sign
            json::Array& ja_infos = jo_result["infos"];
            for (size_t n = 0; n < ja_infos.Size(); n++) {
                switch (IssVerifySign(
                    ja_infos[n]["info_key"].Pack().c_str(),
                    atoi(ja_infos[n]["info_version"].Pack().c_str()),
                    atoi(ja_infos[n]["state"].Pack().c_str()),
                    ja_infos[n]["content"].Pack().c_str(),
                    ja_infos[n]["notes"].Pack().c_str(),
                    ja_infos[n]["commit_time"].Pack().c_str(),
                    ja_infos[n]["public_key"].Pack().c_str(),
                    ja_infos[n]["sign"].Pack().c_str())) {
                case 0:
                    ja_infos[n]["sign_verify"] = true;
                    break;
                case 1:
                    ja_infos[n]["sign_verify"] = false;
                    break;
                default:
                    ja_infos[n]["error"] = GetErrorStr();
                    break;
                }
            }
#endif
        }

        result[i] = jo_result;
    }

    return result;
}


json::Array tDamAssetIssueApply(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 发行方渠道编号	channel_id
    // 原资产唯一ID	source_id
    // 持有方帐户	owner_account
    // 资产类型	asset_type
    // 资产份额	amount
    // 资产单位	unit
    // 资产内容	content
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];
        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "content") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_issue_apply.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetIssueSubmit(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 交易ID	transaction_id
    // 资产类型	asset_type
    // 签名列表	sign_list
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char sign[SIGN_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        std::string private_key = params[i]["private_key"].Pack();
        strncpy(prvkey, private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, private_key.size()));

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];

        // 签名得到sign_list.sign 补全到请求参数列表
        std::string sign_str = jo_params["sign_list"]["sign_str"].Pack();
        if (SignString(prvkey, sign_str.c_str(), (int)sign_str.size(), sign) == 0) {
            jo_params["sign_list"]["sign"] = sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "sign_list") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_issue_submit.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetTransferApply(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 资产转出帐户	src_account
    // 资产转入帐户	dst_account
    // 资产类型	asset_type
    // 转让份额	amount
    // 要求签收时间	sign_in_date
    // 扩展信息	extra_info
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];
        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "extra_info") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_transfer_apply.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetTransferSign(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 交易ID	transaction_id
    // 资产类型	asset_type
    // 操作类型	op_code
    // 签名列表	sign_list
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char sign[SIGN_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        std::string private_key = params[i]["private_key"].Pack();
        strncpy(prvkey, private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, private_key.size()));

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];

        // 签名得到sign_list.sign 补全到请求参数列表
        std::string sign_str = jo_params["sign_list"]["sign_str"].Pack();
        if (SignString(prvkey, sign_str.c_str(), (int)sign_str.size(), sign) == 0) {
            jo_params["sign_list"]["sign"] = sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "sign_list") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_transfer_sign.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetTransferSubmit(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 交易ID	transaction_id
    // 资产类型	asset_type
    // 签名列表	sign_list
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char sign[SIGN_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        std::string private_key = params[i]["private_key"].Pack();
        strncpy(prvkey, private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, private_key.size()));

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];

        // 签名得到sign_list.sign 补全到请求参数列表
        std::string sign_str = jo_params["sign_list"]["sign_str"].Pack();
        if (SignString(prvkey, sign_str.c_str(), (int)sign_str.size(), sign) == 0) {
            jo_params["sign_list"]["sign"] = sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "sign_list") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_transfer_submit.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetSettleApply(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 持有方帐户	owner_account
    // 资产类型	asset_type
    // 份额	amount
    // 扩展信息	extra_info
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];
        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "extra_info") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_settle_apply.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetSettleSubmit(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 交易ID	transaction_id
    // 资产类型	asset_type
    // 签名列表	sign_list
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char sign[SIGN_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        std::string private_key = params[i]["private_key"].Pack();
        strncpy(prvkey, private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, private_key.size()));

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];

        // 签名得到sign_list.sign 补全到请求参数列表
        std::string sign_str = jo_params["sign_list"]["sign_str"].Pack();
        if (SignString(prvkey, sign_str.c_str(), (int)sign_str.size(), sign) == 0) {
            jo_params["sign_list"]["sign"] = sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            if (it->first == "sign_list") {
                jo_data[it->first] = json::Object(it->second);
            }
            else {
                jo_data[it->first] = it->second;
            }
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_settle_submit.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetQuery(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 资产帐户	asset_account
    // 交易ID	transaction_id
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];
        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            jo_data[it->first] = it->second;
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_query.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetAccountQuery(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 用户ID	owner_uid
    // 资产帐户	asset_account
    // 查询条数	limit
    // 页数	page_no
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];
        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            jo_data[it->first] = it->second;
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_account_query.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}

json::Array tDamAssetTransQuery(const std::string& mch_id, const std::string& mch_private_key, const json::Array& params, const args_options& opt)
{
    json::Array result;
    result.Resize(params.Size());

    // 接口版本		version
    // 签名方式		sign_type
    // 通讯方ID		mch_id
    // 通讯方签名	mch_sign
    // 业务参数
    // 发起方	src_account
    // 接收方	dst_account
    // 交易ID	transaction_id
    // 交易类型	trans_type
    // 交易状态	state
    // 查询条数	limit
    // 页数	page_no
    // 查询月份	month
    // 请求时间	timestamp

    for (size_t i = 0; i < params.Size(); i++) {
        char mch_prvkey[PRVKEY_DIGEST_LENGTH] = { 0 };
        char mch_sign[SIGN_DIGEST_LENGTH] = { 0 };

        // 准备请求参数列表
        std::map<std::string, std::string> mpsig;
        mpsig["sign_type"] = "ECDSA";
        mpsig["mch_id"] = mch_id;
        mpsig["timestamp"] = toString(time(0));

        // 拼接请求参数列表
        json::Object jo_params = params[i];
        for (json::Object::iterator it = jo_params.Begin(); it != jo_params.End(); ++it) {
            mpsig[it->name] = it->element.Pack();
        }

        // 请求post data的内容(json)
        json::Object jo_data;

        // 组建mch_sign的签名原串
        std::string sigss;
        for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
            sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;

            jo_data[it->first] = it->second;
        }

        if (opt.verbose) {
            fprintf(stdout, "text_src:%s\n", sigss.c_str());
            fprintf(stdout, "text_hex:");
            for (std::string::iterator it = sigss.begin(); it != sigss.end(); ++it) {
                fprintf(stdout, "%02x", (unsigned char)*it);
            }
            fprintf(stdout, "\n");
        }

        strncpy(mch_prvkey, mch_private_key.c_str(), min(PRVKEY_DIGEST_LENGTH, mch_private_key.size()));

        // 签名得到mch_sign 补全到请求参数列表
        if (SignString(mch_prvkey, sigss.c_str(), (int)sigss.size(), mch_sign) == 0) {
            jo_data["mch_sign"] = mch_sign;
        }
        else {
            result[i]["error"] = GetErrorStr();
            continue;
        }

        // http请求开始
        chttp_request req(chttp_post);
        req.url = std::string(HTTP_PROTOCOL "://") + opt.domain + "/cgi-bin/v1.0/dam_asset_trans_query.cgi";
        HTTP_HEADERS(req.headers);
        req.data = jo_data.Pack();

        if (opt.verbose) {
            fprintf(stdout, "post_data:%s\n", req.data.c_str());
        }

        chttp_response rsp;

        chttp_client cli;
        cli.proxy = opt.proxy;
        cli.verbose = opt.verbose ? 1L : 0L;

        if (cli.perform(req, rsp) != 0)
        {
            result[i]["error"] = cli.get_last_error();
            continue;
        }

        if (!rsp.is_successed())
        {
            result[i]["error"] = std::string("http unsuccessed: ") + toString(rsp.rescode);
            continue;
        }

        if (rsp.data.empty())
        {
            result[i]["error"] = "ResponseData empty";
            continue;
        }

        // 分析http请求结果
        json::Object jo_result(rsp.data);

        if (jo_result["retcode"].Pack() == "0" && jo_result["retmsg"].Pack() == "OK") {
            mpsig.clear();
            sigss.clear();

            // 拼接返回数据的mch_sign签名源串
            for (json::Object::iterator it = jo_result.Begin(); it != jo_result.End(); ++it) {
                if (it->name != "mch_sign") {
                    mpsig[it->name] = it->element.Pack();
                }
            }
            for (std::map<std::string, std::string>::iterator it = mpsig.begin(); it != mpsig.end(); ++it) {
                sigss += std::string(sigss.empty() ? "" : "&") + it->first + "=" + it->second;
            }

            // 验证返回数据的mch_sign
            switch (VerifySign(s_dam_pubkey, sigss.c_str(), (int)sigss.size(), jo_result["mch_sign"].Pack().c_str())) {
            case 0:
                jo_result["mch_sign_verify"] = true;
                break;
            case 1:
                jo_result["mch_sign_verify"] = false;
                break;
            default:
                jo_result["error"] = GetErrorStr();
                break;
            }
        }

        result[i] = jo_result;
    }

    return result;
}


void show_help(const char* app)
{
    fprintf(stdout, "\nUsage: %s <command> <parameters> [options]\n", app);
    fprintf(stdout, "\ncommand:\n");
    fprintf(stdout, "tGeneratePairkey [count]\n");
    fprintf(stdout, "tCheckPairkey <'[\"private_key\",\"public_key\", ...]'>\n");
    fprintf(stdout, "tGeneratePubkeyByPrvkey <'[\"private_key\", ...]'>\n");
    fprintf(stdout, "tGenerateAddrByPubkey <'[\"public_key\", ...]'>\n");
    fprintf(stdout, "tGenerateAddrByPrvkey <'[\"private_key\", ...]'>\n");
    fprintf(stdout, "tSignString <'private_key'> <'text'>\n");
    fprintf(stdout, "tVerifySign <'public_key'> <'text'> <'sign'>\n");
    fprintf(stdout, "tIssAppend <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"info_key\",\"info_version\",\"state\",\"content\",\"notes\",\"commit_time\",\"private_key\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tIssQuery <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"info_key\",\"state\",\"content\",\"notes\",\"range\",\"account\",\"t_hash\",\"page_no\",\"page_limit\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetIssueApply <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"channel_id\",\"source_id\",\"owner_account\",\"asset_type\",\"amount\",\"unit\",\"content\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetIssueSubmit <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"transaction_id\",\"asset_type\",\"sign_list\",\"private_key\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetTransferApply <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"src_account\",\"dst_account\",\"asset_type\",\"amount\",\"sign_in_date\",\"extra_info\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetTransferSign <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"transaction_id\",\"asset_type\",\"op_code\",\"sign_list\",\"private_key\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetTransferSubmit <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"transaction_id\",\"asset_type\",\"sign_list\",\"private_key\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetSettleApply <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"owner_account\",\"asset_type\",\"amount\",\"extra_info\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetSettleSubmit <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"transaction_id\",\"asset_type\",\"sign_list\",\"private_key\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetQuery <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"asset_account\",\"transaction_id\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetAccountQuery <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"owner_uid\",\"asset_account\",\"limit\",\"page_no\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "tDamAssetTransQuery <mch_id> <mch_private_key> <'[{\"version\",\"node_id\",\"chain_id\",\"ledger_id\",\"src_account\",\"dst_account\",\"transaction_id\",\"trans_type\",\"state\",\"limit\",\"page_no\",\"month\"} , ...]'> [--domain \"\"] [--proxy \"\"] [--verbose]\n");
    fprintf(stdout, "\n");
}

int main(int argc, char* argv[])
{
    try {
        do {
            if (argc < 2) {
                break;
            }

            SetCharset(CHAR_LOCATE);

            json::Array result;
            std::string command = argv[1];

            if (command == "help" || command == "--help" || command == "-h") {
                break;
            }
            else if (command == "tGeneratePairkey") {
                size_t count = 1;
                if (argc >= 3) {
                    char* end;
                    count = strtoull(argv[2], &end, 10);
                }

                result = tGeneratePairkey(count);
            }
            else if (command == "tCheckPairkey") {
                if (argc < 3) {
                    break;
                }

                json::Array params(argv[2]);

                result = tCheckPairkey(params);
            }
            else if (command == "tGeneratePubkeyByPrvkey") {
                if (argc < 3) {
                    break;
                }

                json::Array params(argv[2]);

                result = tGeneratePubkeyByPrvkey(params);
            }
            else if (command == "tGenerateAddrByPubkey") {
                if (argc < 3) {
                    break;
                }

                json::Array params(argv[2]);

                result = tGenerateAddrByPubkey(params);
            }
            else if (command == "tGenerateAddrByPrvkey") {
                if (argc < 3) {
                    break;
                }

                json::Array params(argv[2]);

                result = tGenerateAddrByPrvkey(params);
            }
            else if (command == "tSignString") {
                if (argc < 4) {
                    break;
                }

                result = tSignString(argv[2], argv[3]);
            }
            else if (command == "tVerifySign") {
                if (argc < 5) {
                    break;
                }

                result = tVerifySign(argv[2], argv[3], argv[4]);
            }
            else if (command == "tIssAppend") {
                if (argc < 5) {
                    break;
                }
				json::Array result = tGeneratePairkey(1);
				std::string key = result[0].Pack();
				char *pData = "[{\"sign\":\"323\",\"version\":\"1.0\",\"info_key\":\"info_key\",\"info_version\":1,\"state\":1,\"content\":{\"a\":1},\"notes\":{\"32\":323},\"commit_time\":\"2019\",\"private_key\":\"MCmc0HWpbiarELNHDgytOkXkuIveaE7FRIEKZxYY4AE=\",\"chain_id\":\"323\",\"ledger_id\":\"323\"}]";
				std::cout << argv[4] << std::endl;
                //json::Array params(argv[4]);
				json::Array params(pData);
                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tIssAppend(argv[2], argv[3], params, opt);
				for (int i = 0; i < result.Size(); ++i)
				{
					std::cout << result[i].Pack() << std::endl;
				}
            }
            else if (command == "tIssQuery") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tIssQuery(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetIssueApply") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetIssueApply(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetIssueSubmit") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetIssueSubmit(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetTransferApply") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetTransferApply(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetTransferSign") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetTransferSign(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetTransferSubmit") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetTransferSubmit(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetSettleApply") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetSettleApply(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetSettleSubmit") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetSettleSubmit(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetQuery") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetQuery(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetAccountQuery") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetAccountQuery(argv[2], argv[3], params, opt);
            }
            else if (command == "tDamAssetTransQuery") {
                if (argc < 5) {
                    break;
                }

                json::Array params(argv[4]);

                args_options opt;
                if (argc > 5) {
                    opt.parse(argc - 4, &argv[4]);
                }

                result = tDamAssetTransQuery(argv[2], argv[3], params, opt);
            }

            result.Dump(std::cout, false);
            std::cout << std::endl;

            return 0;

        } while (0);
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    show_help(argv[0]);

    return 0;
}
