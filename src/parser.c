#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#ifdef _MSC_VER
#pragma optimize("", off)
#elif defined(__clang__)
#pragma clang optimize off
#elif defined(__GNUC__)
#pragma GCC optimize ("O0")
#endif

#define LANGUAGE_VERSION 14
#define STATE_COUNT 122
#define LARGE_STATE_COUNT 28
#define SYMBOL_COUNT 142
#define ALIAS_COUNT 0
#define TOKEN_COUNT 99
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 12
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 9

enum {
  anon_sym_in = 1,
  anon_sym_AMP_AMP = 2,
  anon_sym_and = 3,
  anon_sym_xor = 4,
  anon_sym_CARET_CARET = 5,
  anon_sym_or = 6,
  anon_sym_PIPE_PIPE = 7,
  anon_sym_LBRACE = 8,
  anon_sym_RBRACE = 9,
  sym_comment = 10,
  anon_sym_eq = 11,
  anon_sym_ne = 12,
  anon_sym_lt = 13,
  anon_sym_le = 14,
  anon_sym_gt = 15,
  anon_sym_ge = 16,
  anon_sym_EQ_EQ = 17,
  anon_sym_BANG_EQ = 18,
  anon_sym_LT = 19,
  anon_sym_LT_EQ = 20,
  anon_sym_GT = 21,
  anon_sym_GT_EQ = 22,
  anon_sym_contains = 23,
  anon_sym_matches = 24,
  anon_sym_TILDE = 25,
  anon_sym_concat = 26,
  anon_sym_LPAREN = 27,
  anon_sym_COMMA = 28,
  anon_sym_RPAREN = 29,
  anon_sym_ends_with = 30,
  anon_sym_len = 31,
  anon_sym_lookup_json_string = 32,
  anon_sym_lower = 33,
  anon_sym_regex_replace = 34,
  anon_sym_remove_bytes = 35,
  anon_sym_starts_with = 36,
  anon_sym_to_string = 37,
  anon_sym_upper = 38,
  anon_sym_url_decode = 39,
  anon_sym_uuidv4 = 40,
  sym_number = 41,
  sym_string = 42,
  anon_sym_true = 43,
  anon_sym_false = 44,
  sym_ipv4 = 45,
  anon_sym_SLASH = 46,
  aux_sym_ip_range_token1 = 47,
  sym_ip_list = 48,
  anon_sym_not = 49,
  anon_sym_BANG = 50,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTsec = 51,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec = 52,
  anon_sym_ip_DOTgeoip_DOTasnum = 53,
  anon_sym_cf_DOTbot_management_DOTscore = 54,
  anon_sym_cf_DOTedge_DOTserver_port = 55,
  anon_sym_cf_DOTthreat_score = 56,
  anon_sym_cf_DOTwaf_DOTscore = 57,
  anon_sym_cf_DOTwaf_DOTscore_DOTsqli = 58,
  anon_sym_cf_DOTwaf_DOTscore_DOTxss = 59,
  anon_sym_cf_DOTwaf_DOTscore_DOTrce = 60,
  anon_sym_ip_DOTsrc = 61,
  anon_sym_cf_DOTedge_DOTserver_ip = 62,
  anon_sym_http_DOTcookie = 63,
  anon_sym_http_DOThost = 64,
  anon_sym_http_DOTreferer = 65,
  anon_sym_http_DOTrequest_DOTfull_uri = 66,
  anon_sym_http_DOTrequest_DOTmethod = 67,
  anon_sym_http_DOTrequest_DOTcookies = 68,
  anon_sym_http_DOTrequest_DOTuri = 69,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 70,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 71,
  anon_sym_http_DOTuser_agent = 72,
  anon_sym_http_DOTrequest_DOTversion = 73,
  anon_sym_http_DOTx_forwarded_for = 74,
  anon_sym_ip_DOTsrc_DOTlat = 75,
  anon_sym_ip_DOTsrc_DOTlon = 76,
  anon_sym_ip_DOTsrc_DOTcity = 77,
  anon_sym_ip_DOTsrc_DOTpostal_code = 78,
  anon_sym_ip_DOTsrc_DOTmetro_code = 79,
  anon_sym_ip_DOTgeoip_DOTcontinent = 80,
  anon_sym_ip_DOTgeoip_DOTcountry = 81,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 82,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 83,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 84,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 85,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 86,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 87,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 88,
  anon_sym_cf_DOThostname_DOTmetadata = 89,
  anon_sym_cf_DOTworker_DOTupstream_zone = 90,
  anon_sym_cf_DOTrandom_seed = 91,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 92,
  anon_sym_ssl = 93,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 94,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 95,
  anon_sym_cf_DOTclient_DOTbot = 96,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 97,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 98,
  sym_source_file = 99,
  sym__expression = 100,
  sym_not_expression = 101,
  sym_in_expression = 102,
  sym_compound_expression = 103,
  sym_ip_set = 104,
  sym_string_set = 105,
  sym_number_set = 106,
  sym_simple_expression = 107,
  sym__bool_lhs = 108,
  sym__number_lhs = 109,
  sym__string_lhs = 110,
  sym_string_func = 111,
  sym_number_func = 112,
  sym_bool_func = 113,
  sym_concat_func = 114,
  sym_ends_with_func = 115,
  sym_len_func = 116,
  sym_lookup_func = 117,
  sym_lower_func = 118,
  sym_regex_replace_func = 119,
  sym_remove_bytes_func = 120,
  sym_starts_with_func = 121,
  sym_to_string_func = 122,
  sym_upper_func = 123,
  sym_url_decode_func = 124,
  sym_uuid_func = 125,
  sym_group = 126,
  sym_boolean = 127,
  sym__ip = 128,
  sym_ip_range = 129,
  sym_not_operator = 130,
  sym_number_field = 131,
  sym_ip_field = 132,
  sym_string_field = 133,
  sym_bytes_field = 134,
  sym_boolean_field = 135,
  aux_sym_source_file_repeat1 = 136,
  aux_sym_ip_set_repeat1 = 137,
  aux_sym_string_set_repeat1 = 138,
  aux_sym_number_set_repeat1 = 139,
  aux_sym_concat_func_repeat1 = 140,
  aux_sym_lookup_func_repeat1 = 141,
};

static const char * const ts_symbol_names[] = {
  [ts_builtin_sym_end] = "end",
  [anon_sym_in] = "in",
  [anon_sym_AMP_AMP] = "&&",
  [anon_sym_and] = "and",
  [anon_sym_xor] = "xor",
  [anon_sym_CARET_CARET] = "^^",
  [anon_sym_or] = "or",
  [anon_sym_PIPE_PIPE] = "||",
  [anon_sym_LBRACE] = "{",
  [anon_sym_RBRACE] = "}",
  [sym_comment] = "comment",
  [anon_sym_eq] = "eq",
  [anon_sym_ne] = "ne",
  [anon_sym_lt] = "lt",
  [anon_sym_le] = "le",
  [anon_sym_gt] = "gt",
  [anon_sym_ge] = "ge",
  [anon_sym_EQ_EQ] = "==",
  [anon_sym_BANG_EQ] = "!=",
  [anon_sym_LT] = "<",
  [anon_sym_LT_EQ] = "<=",
  [anon_sym_GT] = ">",
  [anon_sym_GT_EQ] = ">=",
  [anon_sym_contains] = "contains",
  [anon_sym_matches] = "matches",
  [anon_sym_TILDE] = "~",
  [anon_sym_concat] = "concat",
  [anon_sym_LPAREN] = "(",
  [anon_sym_COMMA] = ",",
  [anon_sym_RPAREN] = ")",
  [anon_sym_ends_with] = "ends_with",
  [anon_sym_len] = "len",
  [anon_sym_lookup_json_string] = "lookup_json_string",
  [anon_sym_lower] = "lower",
  [anon_sym_regex_replace] = "regex_replace",
  [anon_sym_remove_bytes] = "remove_bytes",
  [anon_sym_starts_with] = "starts_with",
  [anon_sym_to_string] = "to_string",
  [anon_sym_upper] = "upper",
  [anon_sym_url_decode] = "url_decode",
  [anon_sym_uuidv4] = "uuidv4",
  [sym_number] = "number",
  [sym_string] = "string",
  [anon_sym_true] = "true",
  [anon_sym_false] = "false",
  [sym_ipv4] = "ipv4",
  [anon_sym_SLASH] = "/",
  [aux_sym_ip_range_token1] = "ip_range_token1",
  [sym_ip_list] = "ip_list",
  [anon_sym_not] = "not",
  [anon_sym_BANG] = "!",
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = "http.request.timestamp.sec",
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = "http.request.timestamp.msec",
  [anon_sym_ip_DOTgeoip_DOTasnum] = "ip.geoip.asnum",
  [anon_sym_cf_DOTbot_management_DOTscore] = "cf.bot_management.score",
  [anon_sym_cf_DOTedge_DOTserver_port] = "cf.edge.server_port",
  [anon_sym_cf_DOTthreat_score] = "cf.threat_score",
  [anon_sym_cf_DOTwaf_DOTscore] = "cf.waf.score",
  [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = "cf.waf.score.sqli",
  [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = "cf.waf.score.xss",
  [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = "cf.waf.score.rce",
  [anon_sym_ip_DOTsrc] = "ip.src",
  [anon_sym_cf_DOTedge_DOTserver_ip] = "cf.edge.server_ip",
  [anon_sym_http_DOTcookie] = "http.cookie",
  [anon_sym_http_DOThost] = "http.host",
  [anon_sym_http_DOTreferer] = "http.referer",
  [anon_sym_http_DOTrequest_DOTfull_uri] = "http.request.full_uri",
  [anon_sym_http_DOTrequest_DOTmethod] = "http.request.method",
  [anon_sym_http_DOTrequest_DOTcookies] = "http.request.cookies",
  [anon_sym_http_DOTrequest_DOTuri] = "http.request.uri",
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = "http.request.uri.path",
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = "http.request.uri.query",
  [anon_sym_http_DOTuser_agent] = "http.user_agent",
  [anon_sym_http_DOTrequest_DOTversion] = "http.request.version",
  [anon_sym_http_DOTx_forwarded_for] = "http.x_forwarded_for",
  [anon_sym_ip_DOTsrc_DOTlat] = "ip.src.lat",
  [anon_sym_ip_DOTsrc_DOTlon] = "ip.src.lon",
  [anon_sym_ip_DOTsrc_DOTcity] = "ip.src.city",
  [anon_sym_ip_DOTsrc_DOTpostal_code] = "ip.src.postal_code",
  [anon_sym_ip_DOTsrc_DOTmetro_code] = "ip.src.metro_code",
  [anon_sym_ip_DOTgeoip_DOTcontinent] = "ip.geoip.continent",
  [anon_sym_ip_DOTgeoip_DOTcountry] = "ip.geoip.country",
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = "ip.geoip.subdivision_1_iso_code",
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = "ip.geoip.subdivision_2_iso_code",
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = "raw.http.request.full_uri",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = "raw.http.request.uri",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = "raw.http.request.uri.path",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = "raw.http.request.uri.query",
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = "cf.bot_management.ja3_hash",
  [anon_sym_cf_DOThostname_DOTmetadata] = "cf.hostname.metadata",
  [anon_sym_cf_DOTworker_DOTupstream_zone] = "cf.worker.upstream_zone",
  [anon_sym_cf_DOTrandom_seed] = "cf.random_seed",
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = "ip.geoip.is_in_european_union",
  [anon_sym_ssl] = "ssl",
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = "cf.bot_management.verified_bot",
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = "cf.bot_management.js_detection.passed",
  [anon_sym_cf_DOTclient_DOTbot] = "cf.client.bot",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = "cf.tls_client_auth.cert_revoked",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = "cf.tls_client_auth.cert_verified",
  [sym_source_file] = "source_file",
  [sym__expression] = "_expression",
  [sym_not_expression] = "not_expression",
  [sym_in_expression] = "in_expression",
  [sym_compound_expression] = "compound_expression",
  [sym_ip_set] = "ip_set",
  [sym_string_set] = "string_set",
  [sym_number_set] = "number_set",
  [sym_simple_expression] = "simple_expression",
  [sym__bool_lhs] = "_bool_lhs",
  [sym__number_lhs] = "_number_lhs",
  [sym__string_lhs] = "_string_lhs",
  [sym_string_func] = "string_func",
  [sym_number_func] = "number_func",
  [sym_bool_func] = "bool_func",
  [sym_concat_func] = "concat_func",
  [sym_ends_with_func] = "ends_with_func",
  [sym_len_func] = "len_func",
  [sym_lookup_func] = "lookup_func",
  [sym_lower_func] = "lower_func",
  [sym_regex_replace_func] = "regex_replace_func",
  [sym_remove_bytes_func] = "remove_bytes_func",
  [sym_starts_with_func] = "starts_with_func",
  [sym_to_string_func] = "to_string_func",
  [sym_upper_func] = "upper_func",
  [sym_url_decode_func] = "url_decode_func",
  [sym_uuid_func] = "uuid_func",
  [sym_group] = "group",
  [sym_boolean] = "boolean",
  [sym__ip] = "_ip",
  [sym_ip_range] = "ip_range",
  [sym_not_operator] = "not_operator",
  [sym_number_field] = "number_field",
  [sym_ip_field] = "ip_field",
  [sym_string_field] = "string_field",
  [sym_bytes_field] = "bytes_field",
  [sym_boolean_field] = "boolean_field",
  [aux_sym_source_file_repeat1] = "source_file_repeat1",
  [aux_sym_ip_set_repeat1] = "ip_set_repeat1",
  [aux_sym_string_set_repeat1] = "string_set_repeat1",
  [aux_sym_number_set_repeat1] = "number_set_repeat1",
  [aux_sym_concat_func_repeat1] = "concat_func_repeat1",
  [aux_sym_lookup_func_repeat1] = "lookup_func_repeat1",
};

static const TSSymbol ts_symbol_map[] = {
  [ts_builtin_sym_end] = ts_builtin_sym_end,
  [anon_sym_in] = anon_sym_in,
  [anon_sym_AMP_AMP] = anon_sym_AMP_AMP,
  [anon_sym_and] = anon_sym_and,
  [anon_sym_xor] = anon_sym_xor,
  [anon_sym_CARET_CARET] = anon_sym_CARET_CARET,
  [anon_sym_or] = anon_sym_or,
  [anon_sym_PIPE_PIPE] = anon_sym_PIPE_PIPE,
  [anon_sym_LBRACE] = anon_sym_LBRACE,
  [anon_sym_RBRACE] = anon_sym_RBRACE,
  [sym_comment] = sym_comment,
  [anon_sym_eq] = anon_sym_eq,
  [anon_sym_ne] = anon_sym_ne,
  [anon_sym_lt] = anon_sym_lt,
  [anon_sym_le] = anon_sym_le,
  [anon_sym_gt] = anon_sym_gt,
  [anon_sym_ge] = anon_sym_ge,
  [anon_sym_EQ_EQ] = anon_sym_EQ_EQ,
  [anon_sym_BANG_EQ] = anon_sym_BANG_EQ,
  [anon_sym_LT] = anon_sym_LT,
  [anon_sym_LT_EQ] = anon_sym_LT_EQ,
  [anon_sym_GT] = anon_sym_GT,
  [anon_sym_GT_EQ] = anon_sym_GT_EQ,
  [anon_sym_contains] = anon_sym_contains,
  [anon_sym_matches] = anon_sym_matches,
  [anon_sym_TILDE] = anon_sym_TILDE,
  [anon_sym_concat] = anon_sym_concat,
  [anon_sym_LPAREN] = anon_sym_LPAREN,
  [anon_sym_COMMA] = anon_sym_COMMA,
  [anon_sym_RPAREN] = anon_sym_RPAREN,
  [anon_sym_ends_with] = anon_sym_ends_with,
  [anon_sym_len] = anon_sym_len,
  [anon_sym_lookup_json_string] = anon_sym_lookup_json_string,
  [anon_sym_lower] = anon_sym_lower,
  [anon_sym_regex_replace] = anon_sym_regex_replace,
  [anon_sym_remove_bytes] = anon_sym_remove_bytes,
  [anon_sym_starts_with] = anon_sym_starts_with,
  [anon_sym_to_string] = anon_sym_to_string,
  [anon_sym_upper] = anon_sym_upper,
  [anon_sym_url_decode] = anon_sym_url_decode,
  [anon_sym_uuidv4] = anon_sym_uuidv4,
  [sym_number] = sym_number,
  [sym_string] = sym_string,
  [anon_sym_true] = anon_sym_true,
  [anon_sym_false] = anon_sym_false,
  [sym_ipv4] = sym_ipv4,
  [anon_sym_SLASH] = anon_sym_SLASH,
  [aux_sym_ip_range_token1] = aux_sym_ip_range_token1,
  [sym_ip_list] = sym_ip_list,
  [anon_sym_not] = anon_sym_not,
  [anon_sym_BANG] = anon_sym_BANG,
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
  [anon_sym_ip_DOTgeoip_DOTasnum] = anon_sym_ip_DOTgeoip_DOTasnum,
  [anon_sym_cf_DOTbot_management_DOTscore] = anon_sym_cf_DOTbot_management_DOTscore,
  [anon_sym_cf_DOTedge_DOTserver_port] = anon_sym_cf_DOTedge_DOTserver_port,
  [anon_sym_cf_DOTthreat_score] = anon_sym_cf_DOTthreat_score,
  [anon_sym_cf_DOTwaf_DOTscore] = anon_sym_cf_DOTwaf_DOTscore,
  [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
  [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = anon_sym_cf_DOTwaf_DOTscore_DOTxss,
  [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = anon_sym_cf_DOTwaf_DOTscore_DOTrce,
  [anon_sym_ip_DOTsrc] = anon_sym_ip_DOTsrc,
  [anon_sym_cf_DOTedge_DOTserver_ip] = anon_sym_cf_DOTedge_DOTserver_ip,
  [anon_sym_http_DOTcookie] = anon_sym_http_DOTcookie,
  [anon_sym_http_DOThost] = anon_sym_http_DOThost,
  [anon_sym_http_DOTreferer] = anon_sym_http_DOTreferer,
  [anon_sym_http_DOTrequest_DOTfull_uri] = anon_sym_http_DOTrequest_DOTfull_uri,
  [anon_sym_http_DOTrequest_DOTmethod] = anon_sym_http_DOTrequest_DOTmethod,
  [anon_sym_http_DOTrequest_DOTcookies] = anon_sym_http_DOTrequest_DOTcookies,
  [anon_sym_http_DOTrequest_DOTuri] = anon_sym_http_DOTrequest_DOTuri,
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = anon_sym_http_DOTrequest_DOTuri_DOTpath,
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = anon_sym_http_DOTrequest_DOTuri_DOTquery,
  [anon_sym_http_DOTuser_agent] = anon_sym_http_DOTuser_agent,
  [anon_sym_http_DOTrequest_DOTversion] = anon_sym_http_DOTrequest_DOTversion,
  [anon_sym_http_DOTx_forwarded_for] = anon_sym_http_DOTx_forwarded_for,
  [anon_sym_ip_DOTsrc_DOTlat] = anon_sym_ip_DOTsrc_DOTlat,
  [anon_sym_ip_DOTsrc_DOTlon] = anon_sym_ip_DOTsrc_DOTlon,
  [anon_sym_ip_DOTsrc_DOTcity] = anon_sym_ip_DOTsrc_DOTcity,
  [anon_sym_ip_DOTsrc_DOTpostal_code] = anon_sym_ip_DOTsrc_DOTpostal_code,
  [anon_sym_ip_DOTsrc_DOTmetro_code] = anon_sym_ip_DOTsrc_DOTmetro_code,
  [anon_sym_ip_DOTgeoip_DOTcontinent] = anon_sym_ip_DOTgeoip_DOTcontinent,
  [anon_sym_ip_DOTgeoip_DOTcountry] = anon_sym_ip_DOTgeoip_DOTcountry,
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = anon_sym_raw_DOThttp_DOTrequest_DOTuri,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = anon_sym_cf_DOTbot_management_DOTja3_hash,
  [anon_sym_cf_DOThostname_DOTmetadata] = anon_sym_cf_DOThostname_DOTmetadata,
  [anon_sym_cf_DOTworker_DOTupstream_zone] = anon_sym_cf_DOTworker_DOTupstream_zone,
  [anon_sym_cf_DOTrandom_seed] = anon_sym_cf_DOTrandom_seed,
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = anon_sym_ip_DOTgeoip_DOTis_in_european_union,
  [anon_sym_ssl] = anon_sym_ssl,
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = anon_sym_cf_DOTbot_management_DOTverified_bot,
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
  [anon_sym_cf_DOTclient_DOTbot] = anon_sym_cf_DOTclient_DOTbot,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
  [sym_source_file] = sym_source_file,
  [sym__expression] = sym__expression,
  [sym_not_expression] = sym_not_expression,
  [sym_in_expression] = sym_in_expression,
  [sym_compound_expression] = sym_compound_expression,
  [sym_ip_set] = sym_ip_set,
  [sym_string_set] = sym_string_set,
  [sym_number_set] = sym_number_set,
  [sym_simple_expression] = sym_simple_expression,
  [sym__bool_lhs] = sym__bool_lhs,
  [sym__number_lhs] = sym__number_lhs,
  [sym__string_lhs] = sym__string_lhs,
  [sym_string_func] = sym_string_func,
  [sym_number_func] = sym_number_func,
  [sym_bool_func] = sym_bool_func,
  [sym_concat_func] = sym_concat_func,
  [sym_ends_with_func] = sym_ends_with_func,
  [sym_len_func] = sym_len_func,
  [sym_lookup_func] = sym_lookup_func,
  [sym_lower_func] = sym_lower_func,
  [sym_regex_replace_func] = sym_regex_replace_func,
  [sym_remove_bytes_func] = sym_remove_bytes_func,
  [sym_starts_with_func] = sym_starts_with_func,
  [sym_to_string_func] = sym_to_string_func,
  [sym_upper_func] = sym_upper_func,
  [sym_url_decode_func] = sym_url_decode_func,
  [sym_uuid_func] = sym_uuid_func,
  [sym_group] = sym_group,
  [sym_boolean] = sym_boolean,
  [sym__ip] = sym__ip,
  [sym_ip_range] = sym_ip_range,
  [sym_not_operator] = sym_not_operator,
  [sym_number_field] = sym_number_field,
  [sym_ip_field] = sym_ip_field,
  [sym_string_field] = sym_string_field,
  [sym_bytes_field] = sym_bytes_field,
  [sym_boolean_field] = sym_boolean_field,
  [aux_sym_source_file_repeat1] = aux_sym_source_file_repeat1,
  [aux_sym_ip_set_repeat1] = aux_sym_ip_set_repeat1,
  [aux_sym_string_set_repeat1] = aux_sym_string_set_repeat1,
  [aux_sym_number_set_repeat1] = aux_sym_number_set_repeat1,
  [aux_sym_concat_func_repeat1] = aux_sym_concat_func_repeat1,
  [aux_sym_lookup_func_repeat1] = aux_sym_lookup_func_repeat1,
};

static const TSSymbolMetadata ts_symbol_metadata[] = {
  [ts_builtin_sym_end] = {
    .visible = false,
    .named = true,
  },
  [anon_sym_in] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_AMP_AMP] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_and] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_xor] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_CARET_CARET] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_or] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_PIPE_PIPE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LBRACE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RBRACE] = {
    .visible = true,
    .named = false,
  },
  [sym_comment] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_eq] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ne] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_lt] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_le] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_gt] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ge] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_EQ_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_BANG_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LT_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GT_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_contains] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_matches] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_TILDE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_concat] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_COMMA] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ends_with] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_len] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_lookup_json_string] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_lower] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_regex_replace] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_remove_bytes] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_starts_with] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_to_string] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_upper] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_url_decode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_uuidv4] = {
    .visible = true,
    .named = false,
  },
  [sym_number] = {
    .visible = true,
    .named = true,
  },
  [sym_string] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_true] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_false] = {
    .visible = true,
    .named = false,
  },
  [sym_ipv4] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_SLASH] = {
    .visible = true,
    .named = false,
  },
  [aux_sym_ip_range_token1] = {
    .visible = false,
    .named = false,
  },
  [sym_ip_list] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_not] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_BANG] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTasnum] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTscore] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTedge_DOTserver_port] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTthreat_score] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTedge_DOTserver_ip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTcookie] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOThost] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTreferer] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTfull_uri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTmethod] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTcookies] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTuser_agent] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTversion] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTx_forwarded_for] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTlat] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTlon] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTcity] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTpostal_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTmetro_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTcontinent] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTcountry] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOThostname_DOTmetadata] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTworker_DOTupstream_zone] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTrandom_seed] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ssl] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTclient_DOTbot] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = {
    .visible = true,
    .named = false,
  },
  [sym_source_file] = {
    .visible = true,
    .named = true,
  },
  [sym__expression] = {
    .visible = false,
    .named = true,
  },
  [sym_not_expression] = {
    .visible = true,
    .named = true,
  },
  [sym_in_expression] = {
    .visible = true,
    .named = true,
  },
  [sym_compound_expression] = {
    .visible = true,
    .named = true,
  },
  [sym_ip_set] = {
    .visible = true,
    .named = true,
  },
  [sym_string_set] = {
    .visible = true,
    .named = true,
  },
  [sym_number_set] = {
    .visible = true,
    .named = true,
  },
  [sym_simple_expression] = {
    .visible = true,
    .named = true,
  },
  [sym__bool_lhs] = {
    .visible = false,
    .named = true,
  },
  [sym__number_lhs] = {
    .visible = false,
    .named = true,
  },
  [sym__string_lhs] = {
    .visible = false,
    .named = true,
  },
  [sym_string_func] = {
    .visible = true,
    .named = true,
  },
  [sym_number_func] = {
    .visible = true,
    .named = true,
  },
  [sym_bool_func] = {
    .visible = true,
    .named = true,
  },
  [sym_concat_func] = {
    .visible = true,
    .named = true,
  },
  [sym_ends_with_func] = {
    .visible = true,
    .named = true,
  },
  [sym_len_func] = {
    .visible = true,
    .named = true,
  },
  [sym_lookup_func] = {
    .visible = true,
    .named = true,
  },
  [sym_lower_func] = {
    .visible = true,
    .named = true,
  },
  [sym_regex_replace_func] = {
    .visible = true,
    .named = true,
  },
  [sym_remove_bytes_func] = {
    .visible = true,
    .named = true,
  },
  [sym_starts_with_func] = {
    .visible = true,
    .named = true,
  },
  [sym_to_string_func] = {
    .visible = true,
    .named = true,
  },
  [sym_upper_func] = {
    .visible = true,
    .named = true,
  },
  [sym_url_decode_func] = {
    .visible = true,
    .named = true,
  },
  [sym_uuid_func] = {
    .visible = true,
    .named = true,
  },
  [sym_group] = {
    .visible = true,
    .named = true,
  },
  [sym_boolean] = {
    .visible = true,
    .named = true,
  },
  [sym__ip] = {
    .visible = false,
    .named = true,
  },
  [sym_ip_range] = {
    .visible = true,
    .named = true,
  },
  [sym_not_operator] = {
    .visible = true,
    .named = true,
  },
  [sym_number_field] = {
    .visible = true,
    .named = true,
  },
  [sym_ip_field] = {
    .visible = true,
    .named = true,
  },
  [sym_string_field] = {
    .visible = true,
    .named = true,
  },
  [sym_bytes_field] = {
    .visible = true,
    .named = true,
  },
  [sym_boolean_field] = {
    .visible = true,
    .named = true,
  },
  [aux_sym_source_file_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_ip_set_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_string_set_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_number_set_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_concat_func_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_lookup_func_repeat1] = {
    .visible = false,
    .named = false,
  },
};

enum {
  field_field = 1,
  field_ip = 2,
  field_keys = 3,
  field_lhs = 4,
  field_mask = 5,
  field_operator = 6,
  field_regex = 7,
  field_replacement = 8,
  field_rhs = 9,
  field_seed = 10,
  field_source = 11,
  field_value = 12,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_field] = "field",
  [field_ip] = "ip",
  [field_keys] = "keys",
  [field_lhs] = "lhs",
  [field_mask] = "mask",
  [field_operator] = "operator",
  [field_regex] = "regex",
  [field_replacement] = "replacement",
  [field_rhs] = "rhs",
  [field_seed] = "seed",
  [field_source] = "source",
  [field_value] = "value",
};

static const TSFieldMapSlice ts_field_map_slices[PRODUCTION_ID_COUNT] = {
  [1] = {.index = 0, .length = 3},
  [2] = {.index = 3, .length = 1},
  [3] = {.index = 4, .length = 1},
  [4] = {.index = 5, .length = 2},
  [5] = {.index = 7, .length = 2},
  [6] = {.index = 9, .length = 2},
  [7] = {.index = 11, .length = 2},
  [8] = {.index = 13, .length = 3},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [3] =
    {field_field, 2},
  [4] =
    {field_seed, 2},
  [5] =
    {field_field, 2},
    {field_keys, 3},
  [7] =
    {field_ip, 0},
    {field_mask, 2},
  [9] =
    {field_field, 2},
    {field_value, 4},
  [11] =
    {field_field, 2},
    {field_replacement, 4},
  [13] =
    {field_regex, 4},
    {field_replacement, 6},
    {field_source, 2},
};

static const TSSymbol ts_alias_sequences[PRODUCTION_ID_COUNT][MAX_ALIAS_SEQUENCE_LENGTH] = {
  [0] = {0},
};

static const uint16_t ts_non_terminal_alias_map[] = {
  0,
};

static const TSStateId ts_primary_state_ids[STATE_COUNT] = {
  [0] = 0,
  [1] = 1,
  [2] = 2,
  [3] = 3,
  [4] = 4,
  [5] = 5,
  [6] = 6,
  [7] = 7,
  [8] = 8,
  [9] = 9,
  [10] = 10,
  [11] = 11,
  [12] = 12,
  [13] = 13,
  [14] = 14,
  [15] = 15,
  [16] = 16,
  [17] = 17,
  [18] = 18,
  [19] = 19,
  [20] = 20,
  [21] = 21,
  [22] = 22,
  [23] = 23,
  [24] = 24,
  [25] = 25,
  [26] = 26,
  [27] = 27,
  [28] = 28,
  [29] = 29,
  [30] = 30,
  [31] = 31,
  [32] = 32,
  [33] = 33,
  [34] = 34,
  [35] = 35,
  [36] = 36,
  [37] = 37,
  [38] = 38,
  [39] = 39,
  [40] = 40,
  [41] = 41,
  [42] = 42,
  [43] = 43,
  [44] = 44,
  [45] = 45,
  [46] = 46,
  [47] = 47,
  [48] = 48,
  [49] = 49,
  [50] = 50,
  [51] = 51,
  [52] = 52,
  [53] = 53,
  [54] = 54,
  [55] = 55,
  [56] = 56,
  [57] = 57,
  [58] = 58,
  [59] = 59,
  [60] = 60,
  [61] = 61,
  [62] = 62,
  [63] = 63,
  [64] = 64,
  [65] = 65,
  [66] = 66,
  [67] = 67,
  [68] = 68,
  [69] = 69,
  [70] = 70,
  [71] = 71,
  [72] = 72,
  [73] = 73,
  [74] = 74,
  [75] = 75,
  [76] = 76,
  [77] = 77,
  [78] = 78,
  [79] = 79,
  [80] = 80,
  [81] = 81,
  [82] = 82,
  [83] = 83,
  [84] = 84,
  [85] = 85,
  [86] = 86,
  [87] = 87,
  [88] = 88,
  [89] = 89,
  [90] = 90,
  [91] = 91,
  [92] = 92,
  [93] = 93,
  [94] = 94,
  [95] = 95,
  [96] = 96,
  [97] = 97,
  [98] = 98,
  [99] = 99,
  [100] = 100,
  [101] = 101,
  [102] = 102,
  [103] = 103,
  [104] = 104,
  [105] = 105,
  [106] = 106,
  [107] = 107,
  [108] = 108,
  [109] = 109,
  [110] = 110,
  [111] = 111,
  [112] = 112,
  [113] = 113,
  [114] = 114,
  [115] = 115,
  [116] = 116,
  [117] = 117,
  [118] = 118,
  [119] = 119,
  [120] = 120,
  [121] = 121,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(617);
      if (lookahead == '!') ADVANCE(675);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(627);
      if (lookahead == '$') ADVANCE(673);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(645);
      if (lookahead == ')') ADVANCE(647);
      if (lookahead == ',') ADVANCE(646);
      if (lookahead == '/') ADVANCE(669);
      if (lookahead == '3') ADVANCE(659);
      if (lookahead == '<') ADVANCE(637);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '>') ADVANCE(639);
      if (lookahead == '^') ADVANCE(53);
      if (lookahead == 'a') ADVANCE(354);
      if (lookahead == 'c') ADVANCE(257);
      if (lookahead == 'e') ADVANCE(362);
      if (lookahead == 'f') ADVANCE(89);
      if (lookahead == 'g') ADVANCE(178);
      if (lookahead == 'h') ADVANCE(542);
      if (lookahead == 'i') ADVANCE(355);
      if (lookahead == 'l') ADVANCE(179);
      if (lookahead == 'm') ADVANCE(96);
      if (lookahead == 'n') ADVANCE(181);
      if (lookahead == 'o') ADVANCE(453);
      if (lookahead == 'r') ADVANCE(91);
      if (lookahead == 's') ADVANCE(500);
      if (lookahead == 't') ADVANCE(390);
      if (lookahead == 'u') ADVANCE(433);
      if (lookahead == 'x') ADVANCE(394);
      if (lookahead == '{') ADVANCE(625);
      if (lookahead == '|') ADVANCE(615);
      if (lookahead == '}') ADVANCE(626);
      if (lookahead == '~') ADVANCE(643);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(660);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(660);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(51);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(627);
      if (lookahead == ')') ADVANCE(647);
      if (lookahead == ',') ADVANCE(646);
      if (lookahead == '<') ADVANCE(637);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '>') ADVANCE(639);
      if (lookahead == 'c') ADVANCE(260);
      if (lookahead == 'e') ADVANCE(450);
      if (lookahead == 'g') ADVANCE(178);
      if (lookahead == 'h') ADVANCE(580);
      if (lookahead == 'i') ADVANCE(356);
      if (lookahead == 'l') ADVANCE(199);
      if (lookahead == 'm') ADVANCE(96);
      if (lookahead == 'n') ADVANCE(180);
      if (lookahead == 'r') ADVANCE(90);
      if (lookahead == '}') ADVANCE(626);
      if (lookahead == '~') ADVANCE(643);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(660);
      END_STATE();
    case 2:
      if (lookahead == '"') ADVANCE(661);
      if (lookahead != 0) ADVANCE(2);
      END_STATE();
    case 3:
      if (lookahead == '#') ADVANCE(627);
      if (lookahead == '3') ADVANCE(671);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(672);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(670);
      END_STATE();
    case 4:
      if (lookahead == '&') ADVANCE(619);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(124);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(271);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(134);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(144);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(106);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(154);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(267);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(322);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(348);
      END_STATE();
    case 14:
      if (lookahead == '.') ADVANCE(48);
      END_STATE();
    case 15:
      if (lookahead == '.') ADVANCE(48);
      if (lookahead == '5') ADVANCE(16);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(14);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(18);
      END_STATE();
    case 16:
      if (lookahead == '.') ADVANCE(48);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(14);
      END_STATE();
    case 17:
      if (lookahead == '.') ADVANCE(48);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(18);
      END_STATE();
    case 18:
      if (lookahead == '.') ADVANCE(48);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(14);
      END_STATE();
    case 19:
      if (lookahead == '.') ADVANCE(125);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(129);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(137);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(155);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(287);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(324);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(127);
      END_STATE();
    case 26:
      if (lookahead == '.') ADVANCE(46);
      END_STATE();
    case 27:
      if (lookahead == '.') ADVANCE(46);
      if (lookahead == '5') ADVANCE(28);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(26);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(30);
      END_STATE();
    case 28:
      if (lookahead == '.') ADVANCE(46);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(26);
      END_STATE();
    case 29:
      if (lookahead == '.') ADVANCE(46);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(30);
      END_STATE();
    case 30:
      if (lookahead == '.') ADVANCE(46);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(26);
      END_STATE();
    case 31:
      if (lookahead == '.') ADVANCE(503);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(442);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(146);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(275);
      END_STATE();
    case 35:
      if (lookahead == '.') ADVANCE(47);
      END_STATE();
    case 36:
      if (lookahead == '.') ADVANCE(47);
      if (lookahead == '5') ADVANCE(37);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(35);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(39);
      END_STATE();
    case 37:
      if (lookahead == '.') ADVANCE(47);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(35);
      END_STATE();
    case 38:
      if (lookahead == '.') ADVANCE(47);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(39);
      END_STATE();
    case 39:
      if (lookahead == '.') ADVANCE(47);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(35);
      END_STATE();
    case 40:
      if (lookahead == '.') ADVANCE(586);
      END_STATE();
    case 41:
      if (lookahead == '.') ADVANCE(346);
      END_STATE();
    case 42:
      if (lookahead == '.') ADVANCE(482);
      END_STATE();
    case 43:
      if (lookahead == '.') ADVANCE(527);
      END_STATE();
    case 44:
      if (lookahead == '.') ADVANCE(135);
      END_STATE();
    case 45:
      if (lookahead == '1') ADVANCE(70);
      if (lookahead == '2') ADVANCE(88);
      END_STATE();
    case 46:
      if (lookahead == '2') ADVANCE(665);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(668);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(667);
      END_STATE();
    case 47:
      if (lookahead == '2') ADVANCE(27);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(29);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(30);
      END_STATE();
    case 48:
      if (lookahead == '2') ADVANCE(36);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(38);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(39);
      END_STATE();
    case 49:
      if (lookahead == '3') ADVANCE(68);
      END_STATE();
    case 50:
      if (lookahead == '4') ADVANCE(658);
      END_STATE();
    case 51:
      if (lookahead == '=') ADVANCE(636);
      END_STATE();
    case 52:
      if (lookahead == '=') ADVANCE(635);
      END_STATE();
    case 53:
      if (lookahead == '^') ADVANCE(622);
      END_STATE();
    case 54:
      if (lookahead == '_') ADVANCE(343);
      END_STATE();
    case 55:
      if (lookahead == '_') ADVANCE(323);
      END_STATE();
    case 56:
      if (lookahead == '_') ADVANCE(123);
      END_STATE();
    case 57:
      if (lookahead == '_') ADVANCE(298);
      END_STATE();
    case 58:
      if (lookahead == '_') ADVANCE(614);
      END_STATE();
    case 59:
      if (lookahead == '_') ADVANCE(45);
      END_STATE();
    case 60:
      if (lookahead == '_') ADVANCE(489);
      END_STATE();
    case 61:
      if (lookahead == '_') ADVANCE(605);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(261);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(504);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(147);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(167);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(300);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(588);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(286);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(102);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(315);
      END_STATE();
    case 71:
      if (lookahead == '_') ADVANCE(209);
      END_STATE();
    case 72:
      if (lookahead == '_') ADVANCE(516);
      END_STATE();
    case 73:
      if (lookahead == '_') ADVANCE(475);
      END_STATE();
    case 74:
      if (lookahead == '_') ADVANCE(591);
      END_STATE();
    case 75:
      if (lookahead == '_') ADVANCE(593);
      END_STATE();
    case 76:
      if (lookahead == '_') ADVANCE(173);
      END_STATE();
    case 77:
      if (lookahead == '_') ADVANCE(607);
      END_STATE();
    case 78:
      if (lookahead == '_') ADVANCE(263);
      END_STATE();
    case 79:
      if (lookahead == '_') ADVANCE(128);
      END_STATE();
    case 80:
      if (lookahead == '_') ADVANCE(119);
      END_STATE();
    case 81:
      if (lookahead == '_') ADVANCE(526);
      END_STATE();
    case 82:
      if (lookahead == '_') ADVANCE(148);
      END_STATE();
    case 83:
      if (lookahead == '_') ADVANCE(529);
      END_STATE();
    case 84:
      if (lookahead == '_') ADVANCE(150);
      END_STATE();
    case 85:
      if (lookahead == '_') ADVANCE(152);
      END_STATE();
    case 86:
      if (lookahead == '_') ADVANCE(153);
      END_STATE();
    case 87:
      if (lookahead == '_') ADVANCE(353);
      END_STATE();
    case 88:
      if (lookahead == '_') ADVANCE(321);
      END_STATE();
    case 89:
      if (lookahead == 'a') ADVANCE(333);
      END_STATE();
    case 90:
      if (lookahead == 'a') ADVANCE(604);
      END_STATE();
    case 91:
      if (lookahead == 'a') ADVANCE(604);
      if (lookahead == 'e') ADVANCE(270);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(258);
      if (lookahead == 'o') ADVANCE(459);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(49);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(49);
      if (lookahead == 's') ADVANCE(76);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(714);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(532);
      END_STATE();
    case 97:
      if (lookahead == 'a') ADVANCE(465);
      END_STATE();
    case 98:
      if (lookahead == 'a') ADVANCE(293);
      END_STATE();
    case 99:
      if (lookahead == 'a') ADVANCE(345);
      END_STATE();
    case 100:
      if (lookahead == 'a') ADVANCE(344);
      END_STATE();
    case 101:
      if (lookahead == 'a') ADVANCE(341);
      END_STATE();
    case 102:
      if (lookahead == 'a') ADVANCE(592);
      END_STATE();
    case 103:
      if (lookahead == 'a') ADVANCE(139);
      END_STATE();
    case 104:
      if (lookahead == 'a') ADVANCE(349);
      END_STATE();
    case 105:
      if (lookahead == 'a') ADVANCE(534);
      END_STATE();
    case 106:
      if (lookahead == 'a') ADVANCE(506);
      if (lookahead == 'c') ADVANCE(393);
      if (lookahead == 'i') ADVANCE(510);
      if (lookahead == 's') ADVANCE(584);
      END_STATE();
    case 107:
      if (lookahead == 'a') ADVANCE(176);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(573);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(536);
      if (lookahead == 'o') ADVANCE(359);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(509);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(525);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(491);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(558);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(552);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(555);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(366);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(273);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(369);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(274);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(377);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(276);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(388);
      END_STATE();
    case 123:
      if (lookahead == 'b') ADVANCE(613);
      END_STATE();
    case 124:
      if (lookahead == 'b') ADVANCE(399);
      if (lookahead == 'c') ADVANCE(332);
      if (lookahead == 'e') ADVANCE(158);
      if (lookahead == 'h') ADVANCE(415);
      if (lookahead == 'r') ADVANCE(116);
      if (lookahead == 't') ADVANCE(283);
      if (lookahead == 'w') ADVANCE(92);
      END_STATE();
    case 125:
      if (lookahead == 'b') ADVANCE(399);
      if (lookahead == 'c') ADVANCE(332);
      if (lookahead == 'e') ADVANCE(158);
      if (lookahead == 'h') ADVANCE(415);
      if (lookahead == 't') ADVANCE(283);
      if (lookahead == 'w') ADVANCE(92);
      END_STATE();
    case 126:
      if (lookahead == 'b') ADVANCE(166);
      END_STATE();
    case 127:
      if (lookahead == 'b') ADVANCE(410);
      END_STATE();
    case 128:
      if (lookahead == 'b') ADVANCE(412);
      END_STATE();
    case 129:
      if (lookahead == 'b') ADVANCE(432);
      if (lookahead == 'h') ADVANCE(415);
      if (lookahead == 'w') ADVANCE(401);
      END_STATE();
    case 130:
      if (lookahead == 'c') ADVANCE(282);
      END_STATE();
    case 131:
      if (lookahead == 'c') ADVANCE(686);
      END_STATE();
    case 132:
      if (lookahead == 'c') ADVANCE(676);
      END_STATE();
    case 133:
      if (lookahead == 'c') ADVANCE(677);
      END_STATE();
    case 134:
      if (lookahead == 'c') ADVANCE(402);
      if (lookahead == 'h') ADVANCE(418);
      if (lookahead == 'r') ADVANCE(185);
      if (lookahead == 'u') ADVANCE(524);
      if (lookahead == 'x') ADVANCE(62);
      END_STATE();
    case 135:
      if (lookahead == 'c') ADVANCE(402);
      if (lookahead == 'h') ADVANCE(418);
      if (lookahead == 'r') ADVANCE(254);
      if (lookahead == 'u') ADVANCE(524);
      if (lookahead == 'x') ADVANCE(62);
      END_STATE();
    case 136:
      if (lookahead == 'c') ADVANCE(416);
      END_STATE();
    case 137:
      if (lookahead == 'c') ADVANCE(393);
      if (lookahead == 's') ADVANCE(584);
      END_STATE();
    case 138:
      if (lookahead == 'c') ADVANCE(8);
      END_STATE();
    case 139:
      if (lookahead == 'c') ADVANCE(190);
      END_STATE();
    case 140:
      if (lookahead == 'c') ADVANCE(192);
      END_STATE();
    case 141:
      if (lookahead == 'c') ADVANCE(575);
      END_STATE();
    case 142:
      if (lookahead == 'c') ADVANCE(105);
      END_STATE();
    case 143:
      if (lookahead == 'c') ADVANCE(105);
      if (lookahead == 't') ADVANCE(98);
      END_STATE();
    case 144:
      if (lookahead == 'c') ADVANCE(304);
      if (lookahead == 'l') ADVANCE(109);
      if (lookahead == 'm') ADVANCE(240);
      if (lookahead == 'p') ADVANCE(419);
      END_STATE();
    case 145:
      if (lookahead == 'c') ADVANCE(421);
      END_STATE();
    case 146:
      if (lookahead == 'c') ADVANCE(243);
      END_STATE();
    case 147:
      if (lookahead == 'c') ADVANCE(338);
      END_STATE();
    case 148:
      if (lookahead == 'c') ADVANCE(420);
      END_STATE();
    case 149:
      if (lookahead == 'c') ADVANCE(423);
      END_STATE();
    case 150:
      if (lookahead == 'c') ADVANCE(422);
      END_STATE();
    case 151:
      if (lookahead == 'c') ADVANCE(425);
      END_STATE();
    case 152:
      if (lookahead == 'c') ADVANCE(424);
      END_STATE();
    case 153:
      if (lookahead == 'c') ADVANCE(426);
      END_STATE();
    case 154:
      if (lookahead == 'c') ADVANCE(429);
      if (lookahead == 'f') ADVANCE(587);
      if (lookahead == 'm') ADVANCE(235);
      if (lookahead == 't') ADVANCE(318);
      if (lookahead == 'u') ADVANCE(470);
      if (lookahead == 'v') ADVANCE(232);
      END_STATE();
    case 155:
      if (lookahead == 'c') ADVANCE(429);
      if (lookahead == 'f') ADVANCE(587);
      if (lookahead == 'm') ADVANCE(235);
      if (lookahead == 'u') ADVANCE(470);
      if (lookahead == 'v') ADVANCE(232);
      END_STATE();
    case 156:
      if (lookahead == 'd') ADVANCE(620);
      END_STATE();
    case 157:
      if (lookahead == 'd') ADVANCE(501);
      END_STATE();
    case 158:
      if (lookahead == 'd') ADVANCE(272);
      END_STATE();
    case 159:
      if (lookahead == 'd') ADVANCE(716);
      END_STATE();
    case 160:
      if (lookahead == 'd') ADVANCE(692);
      END_STATE();
    case 161:
      if (lookahead == 'd') ADVANCE(722);
      END_STATE();
    case 162:
      if (lookahead == 'd') ADVANCE(723);
      END_STATE();
    case 163:
      if (lookahead == 'd') ADVANCE(720);
      END_STATE();
    case 164:
      if (lookahead == 'd') ADVANCE(599);
      END_STATE();
    case 165:
      if (lookahead == 'd') ADVANCE(395);
      END_STATE();
    case 166:
      if (lookahead == 'd') ADVANCE(296);
      END_STATE();
    case 167:
      if (lookahead == 'd') ADVANCE(200);
      END_STATE();
    case 168:
      if (lookahead == 'd') ADVANCE(186);
      END_STATE();
    case 169:
      if (lookahead == 'd') ADVANCE(79);
      END_STATE();
    case 170:
      if (lookahead == 'd') ADVANCE(212);
      END_STATE();
    case 171:
      if (lookahead == 'd') ADVANCE(193);
      END_STATE();
    case 172:
      if (lookahead == 'd') ADVANCE(194);
      END_STATE();
    case 173:
      if (lookahead == 'd') ADVANCE(241);
      END_STATE();
    case 174:
      if (lookahead == 'd') ADVANCE(197);
      END_STATE();
    case 175:
      if (lookahead == 'd') ADVANCE(198);
      END_STATE();
    case 176:
      if (lookahead == 'd') ADVANCE(113);
      END_STATE();
    case 177:
      if (lookahead == 'd') ADVANCE(78);
      END_STATE();
    case 178:
      if (lookahead == 'e') ADVANCE(634);
      if (lookahead == 't') ADVANCE(633);
      END_STATE();
    case 179:
      if (lookahead == 'e') ADVANCE(632);
      if (lookahead == 'o') ADVANCE(391);
      if (lookahead == 't') ADVANCE(630);
      END_STATE();
    case 180:
      if (lookahead == 'e') ADVANCE(629);
      END_STATE();
    case 181:
      if (lookahead == 'e') ADVANCE(629);
      if (lookahead == 'o') ADVANCE(533);
      END_STATE();
    case 182:
      if (lookahead == 'e') ADVANCE(608);
      END_STATE();
    case 183:
      if (lookahead == 'e') ADVANCE(662);
      END_STATE();
    case 184:
      if (lookahead == 'e') ADVANCE(663);
      END_STATE();
    case 185:
      if (lookahead == 'e') ADVANCE(264);
      END_STATE();
    case 186:
      if (lookahead == 'e') ADVANCE(657);
      END_STATE();
    case 187:
      if (lookahead == 'e') ADVANCE(688);
      END_STATE();
    case 188:
      if (lookahead == 'e') ADVANCE(452);
      END_STATE();
    case 189:
      if (lookahead == 'e') ADVANCE(682);
      END_STATE();
    case 190:
      if (lookahead == 'e') ADVANCE(652);
      END_STATE();
    case 191:
      if (lookahead == 'e') ADVANCE(681);
      END_STATE();
    case 192:
      if (lookahead == 'e') ADVANCE(685);
      END_STATE();
    case 193:
      if (lookahead == 'e') ADVANCE(704);
      END_STATE();
    case 194:
      if (lookahead == 'e') ADVANCE(703);
      END_STATE();
    case 195:
      if (lookahead == 'e') ADVANCE(679);
      END_STATE();
    case 196:
      if (lookahead == 'e') ADVANCE(715);
      END_STATE();
    case 197:
      if (lookahead == 'e') ADVANCE(707);
      END_STATE();
    case 198:
      if (lookahead == 'e') ADVANCE(708);
      END_STATE();
    case 199:
      if (lookahead == 'e') ADVANCE(631);
      if (lookahead == 't') ADVANCE(630);
      END_STATE();
    case 200:
      if (lookahead == 'e') ADVANCE(136);
      END_STATE();
    case 201:
      if (lookahead == 'e') ADVANCE(370);
      END_STATE();
    case 202:
      if (lookahead == 'e') ADVANCE(437);
      END_STATE();
    case 203:
      if (lookahead == 'e') ADVANCE(455);
      END_STATE();
    case 204:
      if (lookahead == 'e') ADVANCE(398);
      END_STATE();
    case 205:
      if (lookahead == 'e') ADVANCE(495);
      END_STATE();
    case 206:
      if (lookahead == 'e') ADVANCE(602);
      END_STATE();
    case 207:
      if (lookahead == 'e') ADVANCE(456);
      END_STATE();
    case 208:
      if (lookahead == 'e') ADVANCE(43);
      END_STATE();
    case 209:
      if (lookahead == 'e') ADVANCE(590);
      END_STATE();
    case 210:
      if (lookahead == 'e') ADVANCE(159);
      END_STATE();
    case 211:
      if (lookahead == 'e') ADVANCE(141);
      END_STATE();
    case 212:
      if (lookahead == 'e') ADVANCE(177);
      END_STATE();
    case 213:
      if (lookahead == 'e') ADVANCE(56);
      END_STATE();
    case 214:
      if (lookahead == 'e') ADVANCE(132);
      END_STATE();
    case 215:
      if (lookahead == 'e') ADVANCE(468);
      END_STATE();
    case 216:
      if (lookahead == 'e') ADVANCE(497);
      END_STATE();
    case 217:
      if (lookahead == 'e') ADVANCE(133);
      END_STATE();
    case 218:
      if (lookahead == 'e') ADVANCE(469);
      END_STATE();
    case 219:
      if (lookahead == 'e') ADVANCE(41);
      END_STATE();
    case 220:
      if (lookahead == 'e') ADVANCE(100);
      END_STATE();
    case 221:
      if (lookahead == 'e') ADVANCE(493);
      END_STATE();
    case 222:
      if (lookahead == 'e') ADVANCE(169);
      END_STATE();
    case 223:
      if (lookahead == 'e') ADVANCE(161);
      END_STATE();
    case 224:
      if (lookahead == 'e') ADVANCE(462);
      END_STATE();
    case 225:
      if (lookahead == 'e') ADVANCE(162);
      END_STATE();
    case 226:
      if (lookahead == 'e') ADVANCE(499);
      END_STATE();
    case 227:
      if (lookahead == 'e') ADVANCE(120);
      END_STATE();
    case 228:
      if (lookahead == 'e') ADVANCE(163);
      END_STATE();
    case 229:
      if (lookahead == 'e') ADVANCE(457);
      END_STATE();
    case 230:
      if (lookahead == 'e') ADVANCE(476);
      END_STATE();
    case 231:
      if (lookahead == 'e') ADVANCE(358);
      if (lookahead == 'o') ADVANCE(391);
      END_STATE();
    case 232:
      if (lookahead == 'e') ADVANCE(474);
      END_STATE();
    case 233:
      if (lookahead == 'e') ADVANCE(556);
      END_STATE();
    case 234:
      if (lookahead == 'e') ADVANCE(210);
      END_STATE();
    case 235:
      if (lookahead == 'e') ADVANCE(550);
      END_STATE();
    case 236:
      if (lookahead == 'e') ADVANCE(480);
      END_STATE();
    case 237:
      if (lookahead == 'e') ADVANCE(464);
      END_STATE();
    case 238:
      if (lookahead == 'e') ADVANCE(466);
      END_STATE();
    case 239:
      if (lookahead == 'e') ADVANCE(375);
      END_STATE();
    case 240:
      if (lookahead == 'e') ADVANCE(563);
      END_STATE();
    case 241:
      if (lookahead == 'e') ADVANCE(570);
      END_STATE();
    case 242:
      if (lookahead == 'e') ADVANCE(108);
      END_STATE();
    case 243:
      if (lookahead == 'e') ADVANCE(487);
      END_STATE();
    case 244:
      if (lookahead == 'e') ADVANCE(350);
      END_STATE();
    case 245:
      if (lookahead == 'e') ADVANCE(378);
      END_STATE();
    case 246:
      if (lookahead == 'e') ADVANCE(515);
      END_STATE();
    case 247:
      if (lookahead == 'e') ADVANCE(379);
      END_STATE();
    case 248:
      if (lookahead == 'e') ADVANCE(517);
      END_STATE();
    case 249:
      if (lookahead == 'e') ADVANCE(380);
      END_STATE();
    case 250:
      if (lookahead == 'e') ADVANCE(518);
      END_STATE();
    case 251:
      if (lookahead == 'e') ADVANCE(519);
      END_STATE();
    case 252:
      if (lookahead == 'e') ADVANCE(383);
      END_STATE();
    case 253:
      if (lookahead == 'e') ADVANCE(494);
      END_STATE();
    case 254:
      if (lookahead == 'e') ADVANCE(265);
      END_STATE();
    case 255:
      if (lookahead == 'e') ADVANCE(428);
      END_STATE();
    case 256:
      if (lookahead == 'e') ADVANCE(352);
      END_STATE();
    case 257:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(357);
      END_STATE();
    case 258:
      if (lookahead == 'f') ADVANCE(31);
      END_STATE();
    case 259:
      if (lookahead == 'f') ADVANCE(19);
      if (lookahead == 'o') ADVANCE(371);
      END_STATE();
    case 260:
      if (lookahead == 'f') ADVANCE(20);
      if (lookahead == 'o') ADVANCE(381);
      END_STATE();
    case 261:
      if (lookahead == 'f') ADVANCE(406);
      END_STATE();
    case 262:
      if (lookahead == 'f') ADVANCE(312);
      END_STATE();
    case 263:
      if (lookahead == 'f') ADVANCE(411);
      END_STATE();
    case 264:
      if (lookahead == 'f') ADVANCE(221);
      if (lookahead == 'q') ADVANCE(589);
      END_STATE();
    case 265:
      if (lookahead == 'f') ADVANCE(221);
      if (lookahead == 'q') ADVANCE(597);
      END_STATE();
    case 266:
      if (lookahead == 'f') ADVANCE(313);
      END_STATE();
    case 267:
      if (lookahead == 'f') ADVANCE(598);
      if (lookahead == 'u') ADVANCE(477);
      END_STATE();
    case 268:
      if (lookahead == 'g') ADVANCE(655);
      END_STATE();
    case 269:
      if (lookahead == 'g') ADVANCE(650);
      END_STATE();
    case 270:
      if (lookahead == 'g') ADVANCE(182);
      if (lookahead == 'm') ADVANCE(392);
      END_STATE();
    case 271:
      if (lookahead == 'g') ADVANCE(204);
      if (lookahead == 's') ADVANCE(460);
      END_STATE();
    case 272:
      if (lookahead == 'g') ADVANCE(208);
      END_STATE();
    case 273:
      if (lookahead == 'g') ADVANCE(244);
      END_STATE();
    case 274:
      if (lookahead == 'g') ADVANCE(245);
      END_STATE();
    case 275:
      if (lookahead == 'g') ADVANCE(255);
      if (lookahead == 's') ADVANCE(473);
      END_STATE();
    case 276:
      if (lookahead == 'g') ADVANCE(256);
      END_STATE();
    case 277:
      if (lookahead == 'h') ADVANCE(648);
      END_STATE();
    case 278:
      if (lookahead == 'h') ADVANCE(654);
      END_STATE();
    case 279:
      if (lookahead == 'h') ADVANCE(695);
      END_STATE();
    case 280:
      if (lookahead == 'h') ADVANCE(711);
      END_STATE();
    case 281:
      if (lookahead == 'h') ADVANCE(713);
      END_STATE();
    case 282:
      if (lookahead == 'h') ADVANCE(205);
      END_STATE();
    case 283:
      if (lookahead == 'h') ADVANCE(471);
      if (lookahead == 'l') ADVANCE(505);
      END_STATE();
    case 284:
      if (lookahead == 'h') ADVANCE(403);
      END_STATE();
    case 285:
      if (lookahead == 'h') ADVANCE(33);
      END_STATE();
    case 286:
      if (lookahead == 'h') ADVANCE(110);
      END_STATE();
    case 287:
      if (lookahead == 'h') ADVANCE(577);
      END_STATE();
    case 288:
      if (lookahead == 'i') ADVANCE(694);
      END_STATE();
    case 289:
      if (lookahead == 'i') ADVANCE(683);
      END_STATE();
    case 290:
      if (lookahead == 'i') ADVANCE(710);
      END_STATE();
    case 291:
      if (lookahead == 'i') ADVANCE(691);
      END_STATE();
    case 292:
      if (lookahead == 'i') ADVANCE(709);
      END_STATE();
    case 293:
      if (lookahead == 'i') ADVANCE(368);
      END_STATE();
    case 294:
      if (lookahead == 'i') ADVANCE(164);
      END_STATE();
    case 295:
      if (lookahead == 'i') ADVANCE(262);
      END_STATE();
    case 296:
      if (lookahead == 'i') ADVANCE(601);
      END_STATE();
    case 297:
      if (lookahead == 'i') ADVANCE(363);
      END_STATE();
    case 298:
      if (lookahead == 'i') ADVANCE(434);
      if (lookahead == 'p') ADVANCE(414);
      END_STATE();
    case 299:
      if (lookahead == 'i') ADVANCE(201);
      END_STATE();
    case 300:
      if (lookahead == 'i') ADVANCE(372);
      END_STATE();
    case 301:
      if (lookahead == 'i') ADVANCE(545);
      END_STATE();
    case 302:
      if (lookahead == 'i') ADVANCE(386);
      END_STATE();
    case 303:
      if (lookahead == 'i') ADVANCE(364);
      END_STATE();
    case 304:
      if (lookahead == 'i') ADVANCE(544);
      END_STATE();
    case 305:
      if (lookahead == 'i') ADVANCE(405);
      END_STATE();
    case 306:
      if (lookahead == 'i') ADVANCE(417);
      END_STATE();
    case 307:
      if (lookahead == 'i') ADVANCE(546);
      END_STATE();
    case 308:
      if (lookahead == 'i') ADVANCE(187);
      END_STATE();
    case 309:
      if (lookahead == 'i') ADVANCE(408);
      END_STATE();
    case 310:
      if (lookahead == 'i') ADVANCE(409);
      END_STATE();
    case 311:
      if (lookahead == 'i') ADVANCE(226);
      END_STATE();
    case 312:
      if (lookahead == 'i') ADVANCE(222);
      END_STATE();
    case 313:
      if (lookahead == 'i') ADVANCE(225);
      END_STATE();
    case 314:
      if (lookahead == 'i') ADVANCE(438);
      END_STATE();
    case 315:
      if (lookahead == 'i') ADVANCE(530);
      END_STATE();
    case 316:
      if (lookahead == 'i') ADVANCE(239);
      END_STATE();
    case 317:
      if (lookahead == 'i') ADVANCE(522);
      END_STATE();
    case 318:
      if (lookahead == 'i') ADVANCE(351);
      END_STATE();
    case 319:
      if (lookahead == 'i') ADVANCE(443);
      END_STATE();
    case 320:
      if (lookahead == 'i') ADVANCE(266);
      END_STATE();
    case 321:
      if (lookahead == 'i') ADVANCE(531);
      END_STATE();
    case 322:
      if (lookahead == 'j') ADVANCE(94);
      if (lookahead == 's') ADVANCE(151);
      if (lookahead == 'v') ADVANCE(236);
      END_STATE();
    case 323:
      if (lookahead == 'j') ADVANCE(508);
      END_STATE();
    case 324:
      if (lookahead == 'j') ADVANCE(93);
      END_STATE();
    case 325:
      if (lookahead == 'k') ADVANCE(582);
      END_STATE();
    case 326:
      if (lookahead == 'k') ADVANCE(223);
      END_STATE();
    case 327:
      if (lookahead == 'k') ADVANCE(308);
      END_STATE();
    case 328:
      if (lookahead == 'k') ADVANCE(215);
      END_STATE();
    case 329:
      if (lookahead == 'k') ADVANCE(311);
      END_STATE();
    case 330:
      if (lookahead == 'l') ADVANCE(718);
      END_STATE();
    case 331:
      if (lookahead == 'l') ADVANCE(65);
      END_STATE();
    case 332:
      if (lookahead == 'l') ADVANCE(299);
      END_STATE();
    case 333:
      if (lookahead == 'l') ADVANCE(502);
      END_STATE();
    case 334:
      if (lookahead == 'l') ADVANCE(103);
      END_STATE();
    case 335:
      if (lookahead == 'l') ADVANCE(289);
      END_STATE();
    case 336:
      if (lookahead == 'l') ADVANCE(74);
      END_STATE();
    case 337:
      if (lookahead == 'l') ADVANCE(336);
      END_STATE();
    case 338:
      if (lookahead == 'l') ADVANCE(316);
      END_STATE();
    case 339:
      if (lookahead == 'l') ADVANCE(75);
      END_STATE();
    case 340:
      if (lookahead == 'l') ADVANCE(339);
      END_STATE();
    case 341:
      if (lookahead == 'l') ADVANCE(84);
      END_STATE();
    case 342:
      if (lookahead == 'm') ADVANCE(678);
      END_STATE();
    case 343:
      if (lookahead == 'm') ADVANCE(118);
      END_STATE();
    case 344:
      if (lookahead == 'm') ADVANCE(58);
      END_STATE();
    case 345:
      if (lookahead == 'm') ADVANCE(219);
      END_STATE();
    case 346:
      if (lookahead == 'm') ADVANCE(233);
      END_STATE();
    case 347:
      if (lookahead == 'm') ADVANCE(72);
      END_STATE();
    case 348:
      if (lookahead == 'm') ADVANCE(520);
      if (lookahead == 's') ADVANCE(214);
      END_STATE();
    case 349:
      if (lookahead == 'm') ADVANCE(441);
      END_STATE();
    case 350:
      if (lookahead == 'm') ADVANCE(247);
      END_STATE();
    case 351:
      if (lookahead == 'm') ADVANCE(250);
      END_STATE();
    case 352:
      if (lookahead == 'm') ADVANCE(252);
      END_STATE();
    case 353:
      if (lookahead == 'm') ADVANCE(122);
      END_STATE();
    case 354:
      if (lookahead == 'n') ADVANCE(156);
      END_STATE();
    case 355:
      if (lookahead == 'n') ADVANCE(618);
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 356:
      if (lookahead == 'n') ADVANCE(618);
      if (lookahead == 'p') ADVANCE(34);
      END_STATE();
    case 357:
      if (lookahead == 'n') ADVANCE(143);
      END_STATE();
    case 358:
      if (lookahead == 'n') ADVANCE(649);
      END_STATE();
    case 359:
      if (lookahead == 'n') ADVANCE(701);
      END_STATE();
    case 360:
      if (lookahead == 'n') ADVANCE(698);
      END_STATE();
    case 361:
      if (lookahead == 'n') ADVANCE(717);
      END_STATE();
    case 362:
      if (lookahead == 'n') ADVANCE(157);
      if (lookahead == 'q') ADVANCE(628);
      END_STATE();
    case 363:
      if (lookahead == 'n') ADVANCE(268);
      END_STATE();
    case 364:
      if (lookahead == 'n') ADVANCE(269);
      END_STATE();
    case 365:
      if (lookahead == 'n') ADVANCE(585);
      END_STATE();
    case 366:
      if (lookahead == 'n') ADVANCE(165);
      END_STATE();
    case 367:
      if (lookahead == 'n') ADVANCE(99);
      END_STATE();
    case 368:
      if (lookahead == 'n') ADVANCE(496);
      END_STATE();
    case 369:
      if (lookahead == 'n') ADVANCE(117);
      END_STATE();
    case 370:
      if (lookahead == 'n') ADVANCE(554);
      END_STATE();
    case 371:
      if (lookahead == 'n') ADVANCE(142);
      END_STATE();
    case 372:
      if (lookahead == 'n') ADVANCE(71);
      END_STATE();
    case 373:
      if (lookahead == 'n') ADVANCE(32);
      END_STATE();
    case 374:
      if (lookahead == 'n') ADVANCE(59);
      END_STATE();
    case 375:
      if (lookahead == 'n') ADVANCE(560);
      END_STATE();
    case 376:
      if (lookahead == 'n') ADVANCE(572);
      if (lookahead == 'u') ADVANCE(385);
      END_STATE();
    case 377:
      if (lookahead == 'n') ADVANCE(67);
      END_STATE();
    case 378:
      if (lookahead == 'n') ADVANCE(538);
      END_STATE();
    case 379:
      if (lookahead == 'n') ADVANCE(562);
      END_STATE();
    case 380:
      if (lookahead == 'n') ADVANCE(539);
      END_STATE();
    case 381:
      if (lookahead == 'n') ADVANCE(548);
      END_STATE();
    case 382:
      if (lookahead == 'n') ADVANCE(196);
      END_STATE();
    case 383:
      if (lookahead == 'n') ADVANCE(569);
      END_STATE();
    case 384:
      if (lookahead == 'n') ADVANCE(309);
      END_STATE();
    case 385:
      if (lookahead == 'n') ADVANCE(564);
      END_STATE();
    case 386:
      if (lookahead == 'n') ADVANCE(249);
      END_STATE();
    case 387:
      if (lookahead == 'n') ADVANCE(81);
      END_STATE();
    case 388:
      if (lookahead == 'n') ADVANCE(121);
      END_STATE();
    case 389:
      if (lookahead == 'o') ADVANCE(63);
      END_STATE();
    case 390:
      if (lookahead == 'o') ADVANCE(63);
      if (lookahead == 'r') ADVANCE(583);
      END_STATE();
    case 391:
      if (lookahead == 'o') ADVANCE(325);
      if (lookahead == 'w') ADVANCE(203);
      END_STATE();
    case 392:
      if (lookahead == 'o') ADVANCE(600);
      END_STATE();
    case 393:
      if (lookahead == 'o') ADVANCE(376);
      END_STATE();
    case 394:
      if (lookahead == 'o') ADVANCE(454);
      END_STATE();
    case 395:
      if (lookahead == 'o') ADVANCE(347);
      END_STATE();
    case 396:
      if (lookahead == 'o') ADVANCE(327);
      END_STATE();
    case 397:
      if (lookahead == 'o') ADVANCE(326);
      END_STATE();
    case 398:
      if (lookahead == 'o') ADVANCE(314);
      END_STATE();
    case 399:
      if (lookahead == 'o') ADVANCE(549);
      END_STATE();
    case 400:
      if (lookahead == 'o') ADVANCE(387);
      END_STATE();
    case 401:
      if (lookahead == 'o') ADVANCE(459);
      END_STATE();
    case 402:
      if (lookahead == 'o') ADVANCE(396);
      END_STATE();
    case 403:
      if (lookahead == 'o') ADVANCE(160);
      END_STATE();
    case 404:
      if (lookahead == 'o') ADVANCE(82);
      END_STATE();
    case 405:
      if (lookahead == 'o') ADVANCE(360);
      END_STATE();
    case 406:
      if (lookahead == 'o') ADVANCE(461);
      END_STATE();
    case 407:
      if (lookahead == 'o') ADVANCE(382);
      END_STATE();
    case 408:
      if (lookahead == 'o') ADVANCE(361);
      END_STATE();
    case 409:
      if (lookahead == 'o') ADVANCE(373);
      END_STATE();
    case 410:
      if (lookahead == 'o') ADVANCE(537);
      END_STATE();
    case 411:
      if (lookahead == 'o') ADVANCE(458);
      END_STATE();
    case 412:
      if (lookahead == 'o') ADVANCE(541);
      END_STATE();
    case 413:
      if (lookahead == 'o') ADVANCE(444);
      END_STATE();
    case 414:
      if (lookahead == 'o') ADVANCE(485);
      END_STATE();
    case 415:
      if (lookahead == 'o') ADVANCE(507);
      END_STATE();
    case 416:
      if (lookahead == 'o') ADVANCE(168);
      END_STATE();
    case 417:
      if (lookahead == 'o') ADVANCE(374);
      END_STATE();
    case 418:
      if (lookahead == 'o') ADVANCE(512);
      END_STATE();
    case 419:
      if (lookahead == 'o') ADVANCE(514);
      END_STATE();
    case 420:
      if (lookahead == 'o') ADVANCE(171);
      END_STATE();
    case 421:
      if (lookahead == 'o') ADVANCE(483);
      END_STATE();
    case 422:
      if (lookahead == 'o') ADVANCE(172);
      END_STATE();
    case 423:
      if (lookahead == 'o') ADVANCE(484);
      END_STATE();
    case 424:
      if (lookahead == 'o') ADVANCE(174);
      END_STATE();
    case 425:
      if (lookahead == 'o') ADVANCE(488);
      END_STATE();
    case 426:
      if (lookahead == 'o') ADVANCE(175);
      END_STATE();
    case 427:
      if (lookahead == 'o') ADVANCE(329);
      END_STATE();
    case 428:
      if (lookahead == 'o') ADVANCE(319);
      END_STATE();
    case 429:
      if (lookahead == 'o') ADVANCE(427);
      END_STATE();
    case 430:
      if (lookahead == 'o') ADVANCE(85);
      END_STATE();
    case 431:
      if (lookahead == 'o') ADVANCE(86);
      END_STATE();
    case 432:
      if (lookahead == 'o') ADVANCE(581);
      END_STATE();
    case 433:
      if (lookahead == 'p') ADVANCE(445);
      if (lookahead == 'r') ADVANCE(331);
      if (lookahead == 'u') ADVANCE(294);
      END_STATE();
    case 434:
      if (lookahead == 'p') ADVANCE(687);
      END_STATE();
    case 435:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 436:
      if (lookahead == 'p') ADVANCE(7);
      END_STATE();
    case 437:
      if (lookahead == 'p') ADVANCE(334);
      END_STATE();
    case 438:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 439:
      if (lookahead == 'p') ADVANCE(42);
      END_STATE();
    case 440:
      if (lookahead == 'p') ADVANCE(55);
      END_STATE();
    case 441:
      if (lookahead == 'p') ADVANCE(13);
      END_STATE();
    case 442:
      if (lookahead == 'p') ADVANCE(111);
      END_STATE();
    case 443:
      if (lookahead == 'p') ADVANCE(21);
      END_STATE();
    case 444:
      if (lookahead == 'p') ADVANCE(227);
      END_STATE();
    case 445:
      if (lookahead == 'p') ADVANCE(207);
      END_STATE();
    case 446:
      if (lookahead == 'p') ADVANCE(114);
      if (lookahead == 'q') ADVANCE(594);
      END_STATE();
    case 447:
      if (lookahead == 'p') ADVANCE(115);
      if (lookahead == 'q') ADVANCE(595);
      END_STATE();
    case 448:
      if (lookahead == 'p') ADVANCE(523);
      END_STATE();
    case 449:
      if (lookahead == 'p') ADVANCE(44);
      END_STATE();
    case 450:
      if (lookahead == 'q') ADVANCE(628);
      END_STATE();
    case 451:
      if (lookahead == 'q') ADVANCE(335);
      END_STATE();
    case 452:
      if (lookahead == 'q') ADVANCE(596);
      END_STATE();
    case 453:
      if (lookahead == 'r') ADVANCE(623);
      END_STATE();
    case 454:
      if (lookahead == 'r') ADVANCE(621);
      END_STATE();
    case 455:
      if (lookahead == 'r') ADVANCE(651);
      END_STATE();
    case 456:
      if (lookahead == 'r') ADVANCE(656);
      END_STATE();
    case 457:
      if (lookahead == 'r') ADVANCE(690);
      END_STATE();
    case 458:
      if (lookahead == 'r') ADVANCE(699);
      END_STATE();
    case 459:
      if (lookahead == 'r') ADVANCE(328);
      END_STATE();
    case 460:
      if (lookahead == 'r') ADVANCE(131);
      END_STATE();
    case 461:
      if (lookahead == 'r') ADVANCE(606);
      END_STATE();
    case 462:
      if (lookahead == 'r') ADVANCE(603);
      END_STATE();
    case 463:
      if (lookahead == 'r') ADVANCE(610);
      END_STATE();
    case 464:
      if (lookahead == 'r') ADVANCE(611);
      END_STATE();
    case 465:
      if (lookahead == 'r') ADVANCE(578);
      END_STATE();
    case 466:
      if (lookahead == 'r') ADVANCE(612);
      END_STATE();
    case 467:
      if (lookahead == 'r') ADVANCE(297);
      END_STATE();
    case 468:
      if (lookahead == 'r') ADVANCE(40);
      END_STATE();
    case 469:
      if (lookahead == 'r') ADVANCE(80);
      END_STATE();
    case 470:
      if (lookahead == 'r') ADVANCE(288);
      END_STATE();
    case 471:
      if (lookahead == 'r') ADVANCE(242);
      END_STATE();
    case 472:
      if (lookahead == 'r') ADVANCE(404);
      END_STATE();
    case 473:
      if (lookahead == 'r') ADVANCE(138);
      END_STATE();
    case 474:
      if (lookahead == 'r') ADVANCE(513);
      END_STATE();
    case 475:
      if (lookahead == 'r') ADVANCE(202);
      END_STATE();
    case 476:
      if (lookahead == 'r') ADVANCE(57);
      END_STATE();
    case 477:
      if (lookahead == 'r') ADVANCE(290);
      END_STATE();
    case 478:
      if (lookahead == 'r') ADVANCE(413);
      END_STATE();
    case 479:
      if (lookahead == 'r') ADVANCE(291);
      END_STATE();
    case 480:
      if (lookahead == 'r') ADVANCE(295);
      END_STATE();
    case 481:
      if (lookahead == 'r') ADVANCE(292);
      END_STATE();
    case 482:
      if (lookahead == 'r') ADVANCE(188);
      END_STATE();
    case 483:
      if (lookahead == 'r') ADVANCE(189);
      END_STATE();
    case 484:
      if (lookahead == 'r') ADVANCE(191);
      END_STATE();
    case 485:
      if (lookahead == 'r') ADVANCE(540);
      END_STATE();
    case 486:
      if (lookahead == 'r') ADVANCE(220);
      END_STATE();
    case 487:
      if (lookahead == 'r') ADVANCE(567);
      END_STATE();
    case 488:
      if (lookahead == 'r') ADVANCE(195);
      END_STATE();
    case 489:
      if (lookahead == 'r') ADVANCE(206);
      if (lookahead == 'v') ADVANCE(253);
      END_STATE();
    case 490:
      if (lookahead == 'r') ADVANCE(140);
      if (lookahead == 's') ADVANCE(451);
      if (lookahead == 'x') ADVANCE(511);
      END_STATE();
    case 491:
      if (lookahead == 'r') ADVANCE(170);
      END_STATE();
    case 492:
      if (lookahead == 'r') ADVANCE(303);
      END_STATE();
    case 493:
      if (lookahead == 'r') ADVANCE(229);
      END_STATE();
    case 494:
      if (lookahead == 'r') ADVANCE(320);
      END_STATE();
    case 495:
      if (lookahead == 's') ADVANCE(642);
      END_STATE();
    case 496:
      if (lookahead == 's') ADVANCE(641);
      END_STATE();
    case 497:
      if (lookahead == 's') ADVANCE(653);
      END_STATE();
    case 498:
      if (lookahead == 's') ADVANCE(684);
      END_STATE();
    case 499:
      if (lookahead == 's') ADVANCE(693);
      END_STATE();
    case 500:
      if (lookahead == 's') ADVANCE(330);
      if (lookahead == 't') ADVANCE(97);
      END_STATE();
    case 501:
      if (lookahead == 's') ADVANCE(61);
      END_STATE();
    case 502:
      if (lookahead == 's') ADVANCE(184);
      END_STATE();
    case 503:
      if (lookahead == 's') ADVANCE(145);
      END_STATE();
    case 504:
      if (lookahead == 's') ADVANCE(553);
      END_STATE();
    case 505:
      if (lookahead == 's') ADVANCE(64);
      END_STATE();
    case 506:
      if (lookahead == 's') ADVANCE(365);
      END_STATE();
    case 507:
      if (lookahead == 's') ADVANCE(547);
      END_STATE();
    case 508:
      if (lookahead == 's') ADVANCE(400);
      END_STATE();
    case 509:
      if (lookahead == 's') ADVANCE(281);
      END_STATE();
    case 510:
      if (lookahead == 's') ADVANCE(66);
      END_STATE();
    case 511:
      if (lookahead == 's') ADVANCE(498);
      END_STATE();
    case 512:
      if (lookahead == 's') ADVANCE(535);
      END_STATE();
    case 513:
      if (lookahead == 's') ADVANCE(305);
      END_STATE();
    case 514:
      if (lookahead == 's') ADVANCE(571);
      END_STATE();
    case 515:
      if (lookahead == 's') ADVANCE(557);
      END_STATE();
    case 516:
      if (lookahead == 's') ADVANCE(234);
      END_STATE();
    case 517:
      if (lookahead == 's') ADVANCE(559);
      END_STATE();
    case 518:
      if (lookahead == 's') ADVANCE(561);
      END_STATE();
    case 519:
      if (lookahead == 's') ADVANCE(568);
      END_STATE();
    case 520:
      if (lookahead == 's') ADVANCE(217);
      END_STATE();
    case 521:
      if (lookahead == 's') ADVANCE(228);
      END_STATE();
    case 522:
      if (lookahead == 's') ADVANCE(306);
      END_STATE();
    case 523:
      if (lookahead == 's') ADVANCE(576);
      END_STATE();
    case 524:
      if (lookahead == 's') ADVANCE(218);
      END_STATE();
    case 525:
      if (lookahead == 's') ADVANCE(521);
      END_STATE();
    case 526:
      if (lookahead == 's') ADVANCE(566);
      END_STATE();
    case 527:
      if (lookahead == 's') ADVANCE(224);
      END_STATE();
    case 528:
      if (lookahead == 's') ADVANCE(77);
      END_STATE();
    case 529:
      if (lookahead == 's') ADVANCE(149);
      END_STATE();
    case 530:
      if (lookahead == 's') ADVANCE(430);
      END_STATE();
    case 531:
      if (lookahead == 's') ADVANCE(431);
      END_STATE();
    case 532:
      if (lookahead == 't') ADVANCE(130);
      END_STATE();
    case 533:
      if (lookahead == 't') ADVANCE(674);
      END_STATE();
    case 534:
      if (lookahead == 't') ADVANCE(644);
      END_STATE();
    case 535:
      if (lookahead == 't') ADVANCE(689);
      END_STATE();
    case 536:
      if (lookahead == 't') ADVANCE(700);
      END_STATE();
    case 537:
      if (lookahead == 't') ADVANCE(721);
      END_STATE();
    case 538:
      if (lookahead == 't') ADVANCE(697);
      END_STATE();
    case 539:
      if (lookahead == 't') ADVANCE(705);
      END_STATE();
    case 540:
      if (lookahead == 't') ADVANCE(680);
      END_STATE();
    case 541:
      if (lookahead == 't') ADVANCE(719);
      END_STATE();
    case 542:
      if (lookahead == 't') ADVANCE(543);
      END_STATE();
    case 543:
      if (lookahead == 't') ADVANCE(436);
      END_STATE();
    case 544:
      if (lookahead == 't') ADVANCE(609);
      END_STATE();
    case 545:
      if (lookahead == 't') ADVANCE(277);
      END_STATE();
    case 546:
      if (lookahead == 't') ADVANCE(278);
      END_STATE();
    case 547:
      if (lookahead == 't') ADVANCE(367);
      END_STATE();
    case 548:
      if (lookahead == 't') ADVANCE(98);
      END_STATE();
    case 549:
      if (lookahead == 't') ADVANCE(54);
      END_STATE();
    case 550:
      if (lookahead == 't') ADVANCE(284);
      END_STATE();
    case 551:
      if (lookahead == 't') ADVANCE(285);
      END_STATE();
    case 552:
      if (lookahead == 't') ADVANCE(279);
      END_STATE();
    case 553:
      if (lookahead == 't') ADVANCE(467);
      END_STATE();
    case 554:
      if (lookahead == 't') ADVANCE(25);
      END_STATE();
    case 555:
      if (lookahead == 't') ADVANCE(280);
      END_STATE();
    case 556:
      if (lookahead == 't') ADVANCE(107);
      END_STATE();
    case 557:
      if (lookahead == 't') ADVANCE(10);
      END_STATE();
    case 558:
      if (lookahead == 't') ADVANCE(95);
      END_STATE();
    case 559:
      if (lookahead == 't') ADVANCE(11);
      END_STATE();
    case 560:
      if (lookahead == 't') ADVANCE(69);
      END_STATE();
    case 561:
      if (lookahead == 't') ADVANCE(104);
      END_STATE();
    case 562:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 563:
      if (lookahead == 't') ADVANCE(472);
      END_STATE();
    case 564:
      if (lookahead == 't') ADVANCE(463);
      END_STATE();
    case 565:
      if (lookahead == 't') ADVANCE(216);
      END_STATE();
    case 566:
      if (lookahead == 't') ADVANCE(492);
      END_STATE();
    case 567:
      if (lookahead == 't') ADVANCE(60);
      END_STATE();
    case 568:
      if (lookahead == 't') ADVANCE(22);
      END_STATE();
    case 569:
      if (lookahead == 't') ADVANCE(24);
      END_STATE();
    case 570:
      if (lookahead == 't') ADVANCE(211);
      END_STATE();
    case 571:
      if (lookahead == 't') ADVANCE(101);
      END_STATE();
    case 572:
      if (lookahead == 't') ADVANCE(302);
      END_STATE();
    case 573:
      if (lookahead == 't') ADVANCE(83);
      END_STATE();
    case 574:
      if (lookahead == 't') ADVANCE(439);
      END_STATE();
    case 575:
      if (lookahead == 't') ADVANCE(310);
      END_STATE();
    case 576:
      if (lookahead == 't') ADVANCE(486);
      END_STATE();
    case 577:
      if (lookahead == 't') ADVANCE(574);
      END_STATE();
    case 578:
      if (lookahead == 't') ADVANCE(528);
      END_STATE();
    case 579:
      if (lookahead == 't') ADVANCE(449);
      END_STATE();
    case 580:
      if (lookahead == 't') ADVANCE(579);
      END_STATE();
    case 581:
      if (lookahead == 't') ADVANCE(87);
      END_STATE();
    case 582:
      if (lookahead == 'u') ADVANCE(440);
      END_STATE();
    case 583:
      if (lookahead == 'u') ADVANCE(183);
      END_STATE();
    case 584:
      if (lookahead == 'u') ADVANCE(126);
      END_STATE();
    case 585:
      if (lookahead == 'u') ADVANCE(342);
      END_STATE();
    case 586:
      if (lookahead == 'u') ADVANCE(448);
      END_STATE();
    case 587:
      if (lookahead == 'u') ADVANCE(337);
      END_STATE();
    case 588:
      if (lookahead == 'u') ADVANCE(384);
      END_STATE();
    case 589:
      if (lookahead == 'u') ADVANCE(246);
      END_STATE();
    case 590:
      if (lookahead == 'u') ADVANCE(478);
      END_STATE();
    case 591:
      if (lookahead == 'u') ADVANCE(479);
      END_STATE();
    case 592:
      if (lookahead == 'u') ADVANCE(551);
      END_STATE();
    case 593:
      if (lookahead == 'u') ADVANCE(481);
      END_STATE();
    case 594:
      if (lookahead == 'u') ADVANCE(237);
      END_STATE();
    case 595:
      if (lookahead == 'u') ADVANCE(238);
      END_STATE();
    case 596:
      if (lookahead == 'u') ADVANCE(248);
      END_STATE();
    case 597:
      if (lookahead == 'u') ADVANCE(251);
      END_STATE();
    case 598:
      if (lookahead == 'u') ADVANCE(340);
      END_STATE();
    case 599:
      if (lookahead == 'v') ADVANCE(50);
      END_STATE();
    case 600:
      if (lookahead == 'v') ADVANCE(213);
      END_STATE();
    case 601:
      if (lookahead == 'v') ADVANCE(317);
      END_STATE();
    case 602:
      if (lookahead == 'v') ADVANCE(397);
      END_STATE();
    case 603:
      if (lookahead == 'v') ADVANCE(230);
      END_STATE();
    case 604:
      if (lookahead == 'w') ADVANCE(23);
      END_STATE();
    case 605:
      if (lookahead == 'w') ADVANCE(301);
      END_STATE();
    case 606:
      if (lookahead == 'w') ADVANCE(112);
      END_STATE();
    case 607:
      if (lookahead == 'w') ADVANCE(307);
      END_STATE();
    case 608:
      if (lookahead == 'x') ADVANCE(73);
      END_STATE();
    case 609:
      if (lookahead == 'y') ADVANCE(702);
      END_STATE();
    case 610:
      if (lookahead == 'y') ADVANCE(706);
      END_STATE();
    case 611:
      if (lookahead == 'y') ADVANCE(696);
      END_STATE();
    case 612:
      if (lookahead == 'y') ADVANCE(712);
      END_STATE();
    case 613:
      if (lookahead == 'y') ADVANCE(565);
      END_STATE();
    case 614:
      if (lookahead == 'z') ADVANCE(407);
      END_STATE();
    case 615:
      if (lookahead == '|') ADVANCE(624);
      END_STATE();
    case 616:
      if (eof) ADVANCE(617);
      if (lookahead == '!') ADVANCE(675);
      if (lookahead == '#') ADVANCE(627);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(645);
      if (lookahead == ')') ADVANCE(647);
      if (lookahead == '/') ADVANCE(669);
      if (lookahead == '2') ADVANCE(15);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '^') ADVANCE(53);
      if (lookahead == 'a') ADVANCE(354);
      if (lookahead == 'c') ADVANCE(259);
      if (lookahead == 'e') ADVANCE(362);
      if (lookahead == 'h') ADVANCE(542);
      if (lookahead == 'i') ADVANCE(435);
      if (lookahead == 'l') ADVANCE(231);
      if (lookahead == 'n') ADVANCE(181);
      if (lookahead == 'o') ADVANCE(453);
      if (lookahead == 'r') ADVANCE(91);
      if (lookahead == 's') ADVANCE(500);
      if (lookahead == 't') ADVANCE(389);
      if (lookahead == 'u') ADVANCE(433);
      if (lookahead == 'x') ADVANCE(394);
      if (lookahead == '|') ADVANCE(615);
      if (lookahead == '}') ADVANCE(626);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(17);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(616)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(18);
      END_STATE();
    case 617:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 618:
      ACCEPT_TOKEN(anon_sym_in);
      END_STATE();
    case 619:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 620:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 621:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 622:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 623:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 624:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 625:
      ACCEPT_TOKEN(anon_sym_LBRACE);
      END_STATE();
    case 626:
      ACCEPT_TOKEN(anon_sym_RBRACE);
      END_STATE();
    case 627:
      ACCEPT_TOKEN(sym_comment);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(627);
      END_STATE();
    case 628:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 629:
      ACCEPT_TOKEN(anon_sym_ne);
      END_STATE();
    case 630:
      ACCEPT_TOKEN(anon_sym_lt);
      END_STATE();
    case 631:
      ACCEPT_TOKEN(anon_sym_le);
      END_STATE();
    case 632:
      ACCEPT_TOKEN(anon_sym_le);
      if (lookahead == 'n') ADVANCE(649);
      END_STATE();
    case 633:
      ACCEPT_TOKEN(anon_sym_gt);
      END_STATE();
    case 634:
      ACCEPT_TOKEN(anon_sym_ge);
      END_STATE();
    case 635:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 636:
      ACCEPT_TOKEN(anon_sym_BANG_EQ);
      END_STATE();
    case 637:
      ACCEPT_TOKEN(anon_sym_LT);
      if (lookahead == '=') ADVANCE(638);
      END_STATE();
    case 638:
      ACCEPT_TOKEN(anon_sym_LT_EQ);
      END_STATE();
    case 639:
      ACCEPT_TOKEN(anon_sym_GT);
      if (lookahead == '=') ADVANCE(640);
      END_STATE();
    case 640:
      ACCEPT_TOKEN(anon_sym_GT_EQ);
      END_STATE();
    case 641:
      ACCEPT_TOKEN(anon_sym_contains);
      END_STATE();
    case 642:
      ACCEPT_TOKEN(anon_sym_matches);
      END_STATE();
    case 643:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 644:
      ACCEPT_TOKEN(anon_sym_concat);
      END_STATE();
    case 645:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 646:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 647:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 648:
      ACCEPT_TOKEN(anon_sym_ends_with);
      END_STATE();
    case 649:
      ACCEPT_TOKEN(anon_sym_len);
      END_STATE();
    case 650:
      ACCEPT_TOKEN(anon_sym_lookup_json_string);
      END_STATE();
    case 651:
      ACCEPT_TOKEN(anon_sym_lower);
      END_STATE();
    case 652:
      ACCEPT_TOKEN(anon_sym_regex_replace);
      END_STATE();
    case 653:
      ACCEPT_TOKEN(anon_sym_remove_bytes);
      END_STATE();
    case 654:
      ACCEPT_TOKEN(anon_sym_starts_with);
      END_STATE();
    case 655:
      ACCEPT_TOKEN(anon_sym_to_string);
      END_STATE();
    case 656:
      ACCEPT_TOKEN(anon_sym_upper);
      END_STATE();
    case 657:
      ACCEPT_TOKEN(anon_sym_url_decode);
      END_STATE();
    case 658:
      ACCEPT_TOKEN(anon_sym_uuidv4);
      END_STATE();
    case 659:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(660);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(660);
      END_STATE();
    case 660:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(660);
      END_STATE();
    case 661:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 662:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 663:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 664:
      ACCEPT_TOKEN(sym_ipv4);
      END_STATE();
    case 665:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '5') ADVANCE(666);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(664);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(667);
      END_STATE();
    case 666:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(664);
      END_STATE();
    case 667:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(664);
      END_STATE();
    case 668:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(667);
      END_STATE();
    case 669:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 670:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      END_STATE();
    case 671:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(670);
      END_STATE();
    case 672:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(670);
      END_STATE();
    case 673:
      ACCEPT_TOKEN(sym_ip_list);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(673);
      END_STATE();
    case 674:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 675:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(636);
      END_STATE();
    case 676:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 677:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 678:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 679:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 680:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 681:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 682:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(490);
      END_STATE();
    case 683:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 684:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 685:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 686:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(144);
      END_STATE();
    case 687:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 688:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 689:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 690:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 691:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 692:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 693:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 694:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(446);
      END_STATE();
    case 695:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 696:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 697:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 698:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 699:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 700:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 701:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 702:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 703:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 704:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 705:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 706:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 707:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 708:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 709:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 710:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(447);
      END_STATE();
    case 711:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 712:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 713:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 714:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 715:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 716:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 717:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 718:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 719:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 720:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 721:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 722:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 723:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_verified);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 616},
  [2] = {.lex_state = 616},
  [3] = {.lex_state = 616},
  [4] = {.lex_state = 616},
  [5] = {.lex_state = 616},
  [6] = {.lex_state = 616},
  [7] = {.lex_state = 616},
  [8] = {.lex_state = 616},
  [9] = {.lex_state = 616},
  [10] = {.lex_state = 616},
  [11] = {.lex_state = 616},
  [12] = {.lex_state = 616},
  [13] = {.lex_state = 616},
  [14] = {.lex_state = 616},
  [15] = {.lex_state = 616},
  [16] = {.lex_state = 616},
  [17] = {.lex_state = 616},
  [18] = {.lex_state = 616},
  [19] = {.lex_state = 616},
  [20] = {.lex_state = 616},
  [21] = {.lex_state = 616},
  [22] = {.lex_state = 616},
  [23] = {.lex_state = 616},
  [24] = {.lex_state = 616},
  [25] = {.lex_state = 616},
  [26] = {.lex_state = 616},
  [27] = {.lex_state = 616},
  [28] = {.lex_state = 616},
  [29] = {.lex_state = 1},
  [30] = {.lex_state = 0},
  [31] = {.lex_state = 0},
  [32] = {.lex_state = 0},
  [33] = {.lex_state = 0},
  [34] = {.lex_state = 0},
  [35] = {.lex_state = 0},
  [36] = {.lex_state = 0},
  [37] = {.lex_state = 0},
  [38] = {.lex_state = 0},
  [39] = {.lex_state = 0},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
  [46] = {.lex_state = 1},
  [47] = {.lex_state = 1},
  [48] = {.lex_state = 1},
  [49] = {.lex_state = 1},
  [50] = {.lex_state = 1},
  [51] = {.lex_state = 1},
  [52] = {.lex_state = 1},
  [53] = {.lex_state = 1},
  [54] = {.lex_state = 1},
  [55] = {.lex_state = 1},
  [56] = {.lex_state = 1},
  [57] = {.lex_state = 1},
  [58] = {.lex_state = 1},
  [59] = {.lex_state = 1},
  [60] = {.lex_state = 1},
  [61] = {.lex_state = 0},
  [62] = {.lex_state = 0},
  [63] = {.lex_state = 616},
  [64] = {.lex_state = 0},
  [65] = {.lex_state = 616},
  [66] = {.lex_state = 1},
  [67] = {.lex_state = 1},
  [68] = {.lex_state = 616},
  [69] = {.lex_state = 1},
  [70] = {.lex_state = 1},
  [71] = {.lex_state = 0},
  [72] = {.lex_state = 0},
  [73] = {.lex_state = 1},
  [74] = {.lex_state = 0},
  [75] = {.lex_state = 1},
  [76] = {.lex_state = 616},
  [77] = {.lex_state = 1},
  [78] = {.lex_state = 0},
  [79] = {.lex_state = 0},
  [80] = {.lex_state = 0},
  [81] = {.lex_state = 0},
  [82] = {.lex_state = 0},
  [83] = {.lex_state = 1},
  [84] = {.lex_state = 0},
  [85] = {.lex_state = 0},
  [86] = {.lex_state = 0},
  [87] = {.lex_state = 0},
  [88] = {.lex_state = 0},
  [89] = {.lex_state = 0},
  [90] = {.lex_state = 0},
  [91] = {.lex_state = 0},
  [92] = {.lex_state = 0},
  [93] = {.lex_state = 0},
  [94] = {.lex_state = 0},
  [95] = {.lex_state = 0},
  [96] = {.lex_state = 3},
  [97] = {.lex_state = 0},
  [98] = {.lex_state = 0},
  [99] = {.lex_state = 0},
  [100] = {.lex_state = 0},
  [101] = {.lex_state = 0},
  [102] = {.lex_state = 0},
  [103] = {.lex_state = 0},
  [104] = {.lex_state = 0},
  [105] = {.lex_state = 0},
  [106] = {.lex_state = 0},
  [107] = {.lex_state = 0},
  [108] = {.lex_state = 0},
  [109] = {.lex_state = 0},
  [110] = {.lex_state = 0},
  [111] = {.lex_state = 0},
  [112] = {.lex_state = 0},
  [113] = {.lex_state = 0},
  [114] = {.lex_state = 1},
  [115] = {.lex_state = 0},
  [116] = {.lex_state = 0},
  [117] = {.lex_state = 0},
  [118] = {.lex_state = 0},
  [119] = {.lex_state = 0},
  [120] = {.lex_state = 0},
  [121] = {.lex_state = 0},
};

static const uint16_t ts_parse_table[LARGE_STATE_COUNT][SYMBOL_COUNT] = {
  [0] = {
    [ts_builtin_sym_end] = ACTIONS(1),
    [anon_sym_in] = ACTIONS(1),
    [anon_sym_AMP_AMP] = ACTIONS(1),
    [anon_sym_and] = ACTIONS(1),
    [anon_sym_xor] = ACTIONS(1),
    [anon_sym_CARET_CARET] = ACTIONS(1),
    [anon_sym_or] = ACTIONS(1),
    [anon_sym_PIPE_PIPE] = ACTIONS(1),
    [anon_sym_LBRACE] = ACTIONS(1),
    [anon_sym_RBRACE] = ACTIONS(1),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(1),
    [anon_sym_ne] = ACTIONS(1),
    [anon_sym_lt] = ACTIONS(1),
    [anon_sym_le] = ACTIONS(1),
    [anon_sym_gt] = ACTIONS(1),
    [anon_sym_ge] = ACTIONS(1),
    [anon_sym_EQ_EQ] = ACTIONS(1),
    [anon_sym_BANG_EQ] = ACTIONS(1),
    [anon_sym_LT] = ACTIONS(1),
    [anon_sym_LT_EQ] = ACTIONS(1),
    [anon_sym_GT] = ACTIONS(1),
    [anon_sym_GT_EQ] = ACTIONS(1),
    [anon_sym_contains] = ACTIONS(1),
    [anon_sym_matches] = ACTIONS(1),
    [anon_sym_TILDE] = ACTIONS(1),
    [anon_sym_concat] = ACTIONS(1),
    [anon_sym_LPAREN] = ACTIONS(1),
    [anon_sym_COMMA] = ACTIONS(1),
    [anon_sym_RPAREN] = ACTIONS(1),
    [anon_sym_ends_with] = ACTIONS(1),
    [anon_sym_len] = ACTIONS(1),
    [anon_sym_lookup_json_string] = ACTIONS(1),
    [anon_sym_lower] = ACTIONS(1),
    [anon_sym_regex_replace] = ACTIONS(1),
    [anon_sym_remove_bytes] = ACTIONS(1),
    [anon_sym_starts_with] = ACTIONS(1),
    [anon_sym_to_string] = ACTIONS(1),
    [anon_sym_upper] = ACTIONS(1),
    [anon_sym_url_decode] = ACTIONS(1),
    [anon_sym_uuidv4] = ACTIONS(1),
    [sym_number] = ACTIONS(1),
    [sym_string] = ACTIONS(1),
    [anon_sym_true] = ACTIONS(1),
    [anon_sym_false] = ACTIONS(1),
    [anon_sym_SLASH] = ACTIONS(1),
    [aux_sym_ip_range_token1] = ACTIONS(1),
    [sym_ip_list] = ACTIONS(1),
    [anon_sym_not] = ACTIONS(1),
    [anon_sym_BANG] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(1),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(1),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(1),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(1),
    [anon_sym_ip_DOTsrc] = ACTIONS(1),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(1),
    [anon_sym_http_DOTcookie] = ACTIONS(1),
    [anon_sym_http_DOThost] = ACTIONS(1),
    [anon_sym_http_DOTreferer] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(1),
    [anon_sym_http_DOTuser_agent] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(1),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(1),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(1),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(1),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(1),
    [anon_sym_ssl] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(1),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(1),
  },
  [1] = {
    [sym_source_file] = STATE(104),
    [sym__expression] = STATE(27),
    [sym_not_expression] = STATE(27),
    [sym_in_expression] = STATE(27),
    [sym_compound_expression] = STATE(27),
    [sym_simple_expression] = STATE(27),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(27),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(5),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_ends_with] = ACTIONS(11),
    [anon_sym_len] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_not] = ACTIONS(33),
    [anon_sym_BANG] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(35),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(35),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(35),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(35),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(41),
    [anon_sym_http_DOTcookie] = ACTIONS(43),
    [anon_sym_http_DOThost] = ACTIONS(43),
    [anon_sym_http_DOTreferer] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_http_DOTuser_agent] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(43),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(43),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(43),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(47),
    [anon_sym_ssl] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(47),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(47),
  },
  [2] = {
    [sym__expression] = STATE(27),
    [sym_not_expression] = STATE(27),
    [sym_in_expression] = STATE(27),
    [sym_compound_expression] = STATE(27),
    [sym_simple_expression] = STATE(27),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(27),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(49),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(51),
    [anon_sym_LPAREN] = ACTIONS(54),
    [anon_sym_ends_with] = ACTIONS(57),
    [anon_sym_len] = ACTIONS(60),
    [anon_sym_lookup_json_string] = ACTIONS(63),
    [anon_sym_lower] = ACTIONS(66),
    [anon_sym_regex_replace] = ACTIONS(69),
    [anon_sym_remove_bytes] = ACTIONS(72),
    [anon_sym_starts_with] = ACTIONS(75),
    [anon_sym_to_string] = ACTIONS(78),
    [anon_sym_upper] = ACTIONS(81),
    [anon_sym_url_decode] = ACTIONS(84),
    [anon_sym_uuidv4] = ACTIONS(87),
    [anon_sym_not] = ACTIONS(90),
    [anon_sym_BANG] = ACTIONS(90),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(93),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(93),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(93),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(93),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(93),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(93),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(93),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(93),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(93),
    [anon_sym_ip_DOTsrc] = ACTIONS(99),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(102),
    [anon_sym_http_DOTcookie] = ACTIONS(105),
    [anon_sym_http_DOThost] = ACTIONS(105),
    [anon_sym_http_DOTreferer] = ACTIONS(105),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(105),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(105),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(105),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(105),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(105),
    [anon_sym_http_DOTuser_agent] = ACTIONS(105),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(105),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(105),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(105),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(105),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(105),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(105),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(105),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(105),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(105),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(105),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(105),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(105),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(105),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(105),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(105),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(105),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(105),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(111),
    [anon_sym_ssl] = ACTIONS(111),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(111),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(111),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(111),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(111),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(111),
  },
  [3] = {
    [sym__expression] = STATE(27),
    [sym_not_expression] = STATE(27),
    [sym_in_expression] = STATE(27),
    [sym_compound_expression] = STATE(27),
    [sym_simple_expression] = STATE(27),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(27),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(114),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_ends_with] = ACTIONS(11),
    [anon_sym_len] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_not] = ACTIONS(33),
    [anon_sym_BANG] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(35),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(35),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(35),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(35),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(41),
    [anon_sym_http_DOTcookie] = ACTIONS(43),
    [anon_sym_http_DOThost] = ACTIONS(43),
    [anon_sym_http_DOTreferer] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_http_DOTuser_agent] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(43),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(43),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(43),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(47),
    [anon_sym_ssl] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(47),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(47),
  },
  [4] = {
    [sym__expression] = STATE(61),
    [sym_not_expression] = STATE(61),
    [sym_in_expression] = STATE(61),
    [sym_compound_expression] = STATE(61),
    [sym_simple_expression] = STATE(61),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(61),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_ends_with] = ACTIONS(11),
    [anon_sym_len] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_not] = ACTIONS(33),
    [anon_sym_BANG] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(35),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(35),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(35),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(35),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(41),
    [anon_sym_http_DOTcookie] = ACTIONS(43),
    [anon_sym_http_DOThost] = ACTIONS(43),
    [anon_sym_http_DOTreferer] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_http_DOTuser_agent] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(43),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(43),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(43),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(47),
    [anon_sym_ssl] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(47),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(47),
  },
  [5] = {
    [sym__expression] = STATE(22),
    [sym_not_expression] = STATE(22),
    [sym_in_expression] = STATE(22),
    [sym_compound_expression] = STATE(22),
    [sym_simple_expression] = STATE(22),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(22),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_ends_with] = ACTIONS(11),
    [anon_sym_len] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_not] = ACTIONS(33),
    [anon_sym_BANG] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(35),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(35),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(35),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(35),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(41),
    [anon_sym_http_DOTcookie] = ACTIONS(43),
    [anon_sym_http_DOThost] = ACTIONS(43),
    [anon_sym_http_DOTreferer] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_http_DOTuser_agent] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(43),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(43),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(43),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(47),
    [anon_sym_ssl] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(47),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(47),
  },
  [6] = {
    [sym__expression] = STATE(24),
    [sym_not_expression] = STATE(24),
    [sym_in_expression] = STATE(24),
    [sym_compound_expression] = STATE(24),
    [sym_simple_expression] = STATE(24),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(24),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_ends_with] = ACTIONS(11),
    [anon_sym_len] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_not] = ACTIONS(33),
    [anon_sym_BANG] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(35),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(35),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(35),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(35),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(41),
    [anon_sym_http_DOTcookie] = ACTIONS(43),
    [anon_sym_http_DOThost] = ACTIONS(43),
    [anon_sym_http_DOTreferer] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_http_DOTuser_agent] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(43),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(43),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(43),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(47),
    [anon_sym_ssl] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(47),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(47),
  },
  [7] = {
    [sym__expression] = STATE(23),
    [sym_not_expression] = STATE(23),
    [sym_in_expression] = STATE(23),
    [sym_compound_expression] = STATE(23),
    [sym_simple_expression] = STATE(23),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(23),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_ends_with] = ACTIONS(11),
    [anon_sym_len] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_not] = ACTIONS(33),
    [anon_sym_BANG] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(35),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(35),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(35),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(35),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(41),
    [anon_sym_http_DOTcookie] = ACTIONS(43),
    [anon_sym_http_DOThost] = ACTIONS(43),
    [anon_sym_http_DOTreferer] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_http_DOTuser_agent] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(43),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(43),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(43),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(47),
    [anon_sym_ssl] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(47),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(47),
  },
  [8] = {
    [sym__expression] = STATE(21),
    [sym_not_expression] = STATE(21),
    [sym_in_expression] = STATE(21),
    [sym_compound_expression] = STATE(21),
    [sym_simple_expression] = STATE(21),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(58),
    [sym__string_lhs] = STATE(47),
    [sym_string_func] = STATE(47),
    [sym_number_func] = STATE(58),
    [sym_bool_func] = STATE(12),
    [sym_concat_func] = STATE(56),
    [sym_ends_with_func] = STATE(11),
    [sym_len_func] = STATE(60),
    [sym_lookup_func] = STATE(56),
    [sym_lower_func] = STATE(56),
    [sym_regex_replace_func] = STATE(56),
    [sym_remove_bytes_func] = STATE(56),
    [sym_starts_with_func] = STATE(11),
    [sym_to_string_func] = STATE(56),
    [sym_upper_func] = STATE(56),
    [sym_url_decode_func] = STATE(56),
    [sym_uuid_func] = STATE(56),
    [sym_group] = STATE(21),
    [sym_not_operator] = STATE(7),
    [sym_number_field] = STATE(58),
    [sym_ip_field] = STATE(64),
    [sym_string_field] = STATE(47),
    [sym_boolean_field] = STATE(12),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_ends_with] = ACTIONS(11),
    [anon_sym_len] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_not] = ACTIONS(33),
    [anon_sym_BANG] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(35),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(35),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(35),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(35),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(41),
    [anon_sym_http_DOTcookie] = ACTIONS(43),
    [anon_sym_http_DOThost] = ACTIONS(43),
    [anon_sym_http_DOTreferer] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_http_DOTuser_agent] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(43),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(43),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(43),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(43),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(43),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(47),
    [anon_sym_ssl] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(47),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(47),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(47),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(47),
  },
  [9] = {
    [ts_builtin_sym_end] = ACTIONS(116),
    [anon_sym_AMP_AMP] = ACTIONS(116),
    [anon_sym_and] = ACTIONS(116),
    [anon_sym_xor] = ACTIONS(116),
    [anon_sym_CARET_CARET] = ACTIONS(116),
    [anon_sym_or] = ACTIONS(116),
    [anon_sym_PIPE_PIPE] = ACTIONS(116),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(116),
    [anon_sym_ne] = ACTIONS(116),
    [anon_sym_EQ_EQ] = ACTIONS(116),
    [anon_sym_BANG_EQ] = ACTIONS(116),
    [anon_sym_concat] = ACTIONS(116),
    [anon_sym_LPAREN] = ACTIONS(116),
    [anon_sym_RPAREN] = ACTIONS(116),
    [anon_sym_ends_with] = ACTIONS(116),
    [anon_sym_len] = ACTIONS(116),
    [anon_sym_lookup_json_string] = ACTIONS(116),
    [anon_sym_lower] = ACTIONS(116),
    [anon_sym_regex_replace] = ACTIONS(116),
    [anon_sym_remove_bytes] = ACTIONS(116),
    [anon_sym_starts_with] = ACTIONS(116),
    [anon_sym_to_string] = ACTIONS(116),
    [anon_sym_upper] = ACTIONS(116),
    [anon_sym_url_decode] = ACTIONS(116),
    [anon_sym_uuidv4] = ACTIONS(116),
    [anon_sym_not] = ACTIONS(116),
    [anon_sym_BANG] = ACTIONS(118),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(116),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(116),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(116),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(116),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(118),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(116),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(116),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(116),
    [anon_sym_ip_DOTsrc] = ACTIONS(118),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(116),
    [anon_sym_http_DOTcookie] = ACTIONS(116),
    [anon_sym_http_DOThost] = ACTIONS(116),
    [anon_sym_http_DOTreferer] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(118),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(116),
    [anon_sym_http_DOTuser_agent] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(116),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(116),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(116),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(116),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(116),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(116),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(116),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(116),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(116),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(116),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(116),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(116),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(118),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(116),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(116),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(116),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(116),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(116),
    [anon_sym_ssl] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(116),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(116),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(116),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(116),
  },
  [10] = {
    [ts_builtin_sym_end] = ACTIONS(120),
    [anon_sym_AMP_AMP] = ACTIONS(120),
    [anon_sym_and] = ACTIONS(120),
    [anon_sym_xor] = ACTIONS(120),
    [anon_sym_CARET_CARET] = ACTIONS(120),
    [anon_sym_or] = ACTIONS(120),
    [anon_sym_PIPE_PIPE] = ACTIONS(120),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(120),
    [anon_sym_ne] = ACTIONS(120),
    [anon_sym_EQ_EQ] = ACTIONS(120),
    [anon_sym_BANG_EQ] = ACTIONS(120),
    [anon_sym_concat] = ACTIONS(120),
    [anon_sym_LPAREN] = ACTIONS(120),
    [anon_sym_RPAREN] = ACTIONS(120),
    [anon_sym_ends_with] = ACTIONS(120),
    [anon_sym_len] = ACTIONS(120),
    [anon_sym_lookup_json_string] = ACTIONS(120),
    [anon_sym_lower] = ACTIONS(120),
    [anon_sym_regex_replace] = ACTIONS(120),
    [anon_sym_remove_bytes] = ACTIONS(120),
    [anon_sym_starts_with] = ACTIONS(120),
    [anon_sym_to_string] = ACTIONS(120),
    [anon_sym_upper] = ACTIONS(120),
    [anon_sym_url_decode] = ACTIONS(120),
    [anon_sym_uuidv4] = ACTIONS(120),
    [anon_sym_not] = ACTIONS(120),
    [anon_sym_BANG] = ACTIONS(122),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(120),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(120),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(120),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(120),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(120),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(122),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(120),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(120),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(120),
    [anon_sym_ip_DOTsrc] = ACTIONS(122),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(120),
    [anon_sym_http_DOTcookie] = ACTIONS(120),
    [anon_sym_http_DOThost] = ACTIONS(120),
    [anon_sym_http_DOTreferer] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(122),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(120),
    [anon_sym_http_DOTuser_agent] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(120),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(120),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(120),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(120),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(120),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(120),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(120),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(120),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(120),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(120),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(120),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(120),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(122),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(120),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(120),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(120),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(120),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(120),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(120),
    [anon_sym_ssl] = ACTIONS(120),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(120),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(120),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(120),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(120),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(120),
  },
  [11] = {
    [ts_builtin_sym_end] = ACTIONS(124),
    [anon_sym_AMP_AMP] = ACTIONS(124),
    [anon_sym_and] = ACTIONS(124),
    [anon_sym_xor] = ACTIONS(124),
    [anon_sym_CARET_CARET] = ACTIONS(124),
    [anon_sym_or] = ACTIONS(124),
    [anon_sym_PIPE_PIPE] = ACTIONS(124),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(124),
    [anon_sym_ne] = ACTIONS(124),
    [anon_sym_EQ_EQ] = ACTIONS(124),
    [anon_sym_BANG_EQ] = ACTIONS(124),
    [anon_sym_concat] = ACTIONS(124),
    [anon_sym_LPAREN] = ACTIONS(124),
    [anon_sym_RPAREN] = ACTIONS(124),
    [anon_sym_ends_with] = ACTIONS(124),
    [anon_sym_len] = ACTIONS(124),
    [anon_sym_lookup_json_string] = ACTIONS(124),
    [anon_sym_lower] = ACTIONS(124),
    [anon_sym_regex_replace] = ACTIONS(124),
    [anon_sym_remove_bytes] = ACTIONS(124),
    [anon_sym_starts_with] = ACTIONS(124),
    [anon_sym_to_string] = ACTIONS(124),
    [anon_sym_upper] = ACTIONS(124),
    [anon_sym_url_decode] = ACTIONS(124),
    [anon_sym_uuidv4] = ACTIONS(124),
    [anon_sym_not] = ACTIONS(124),
    [anon_sym_BANG] = ACTIONS(126),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(124),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(124),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(124),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(124),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(124),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(124),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(126),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(124),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(124),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(124),
    [anon_sym_ip_DOTsrc] = ACTIONS(126),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(124),
    [anon_sym_http_DOTcookie] = ACTIONS(124),
    [anon_sym_http_DOThost] = ACTIONS(124),
    [anon_sym_http_DOTreferer] = ACTIONS(124),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(124),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(124),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(124),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(126),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(124),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(124),
    [anon_sym_http_DOTuser_agent] = ACTIONS(124),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(124),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(124),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(124),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(124),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(124),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(124),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(124),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(124),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(124),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(124),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(124),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(124),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(126),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(124),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(124),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(124),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(124),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(124),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(124),
    [anon_sym_ssl] = ACTIONS(124),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(124),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(124),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(124),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(124),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(124),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(128),
    [anon_sym_AMP_AMP] = ACTIONS(128),
    [anon_sym_and] = ACTIONS(128),
    [anon_sym_xor] = ACTIONS(128),
    [anon_sym_CARET_CARET] = ACTIONS(128),
    [anon_sym_or] = ACTIONS(128),
    [anon_sym_PIPE_PIPE] = ACTIONS(128),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(130),
    [anon_sym_ne] = ACTIONS(130),
    [anon_sym_EQ_EQ] = ACTIONS(130),
    [anon_sym_BANG_EQ] = ACTIONS(130),
    [anon_sym_concat] = ACTIONS(128),
    [anon_sym_LPAREN] = ACTIONS(128),
    [anon_sym_RPAREN] = ACTIONS(128),
    [anon_sym_ends_with] = ACTIONS(128),
    [anon_sym_len] = ACTIONS(128),
    [anon_sym_lookup_json_string] = ACTIONS(128),
    [anon_sym_lower] = ACTIONS(128),
    [anon_sym_regex_replace] = ACTIONS(128),
    [anon_sym_remove_bytes] = ACTIONS(128),
    [anon_sym_starts_with] = ACTIONS(128),
    [anon_sym_to_string] = ACTIONS(128),
    [anon_sym_upper] = ACTIONS(128),
    [anon_sym_url_decode] = ACTIONS(128),
    [anon_sym_uuidv4] = ACTIONS(128),
    [anon_sym_not] = ACTIONS(128),
    [anon_sym_BANG] = ACTIONS(132),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(128),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(128),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(128),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(128),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(128),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(132),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(128),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(128),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(128),
    [anon_sym_ip_DOTsrc] = ACTIONS(132),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(128),
    [anon_sym_http_DOTcookie] = ACTIONS(128),
    [anon_sym_http_DOThost] = ACTIONS(128),
    [anon_sym_http_DOTreferer] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(132),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(128),
    [anon_sym_http_DOTuser_agent] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(128),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(128),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(128),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(128),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(128),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(128),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(128),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(128),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(128),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(128),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(128),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(128),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(132),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(128),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(128),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(128),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(128),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(128),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(128),
    [anon_sym_ssl] = ACTIONS(128),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(128),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(128),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(128),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(128),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(128),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(134),
    [anon_sym_AMP_AMP] = ACTIONS(134),
    [anon_sym_and] = ACTIONS(134),
    [anon_sym_xor] = ACTIONS(134),
    [anon_sym_CARET_CARET] = ACTIONS(134),
    [anon_sym_or] = ACTIONS(134),
    [anon_sym_PIPE_PIPE] = ACTIONS(134),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(134),
    [anon_sym_ne] = ACTIONS(134),
    [anon_sym_EQ_EQ] = ACTIONS(134),
    [anon_sym_BANG_EQ] = ACTIONS(134),
    [anon_sym_concat] = ACTIONS(134),
    [anon_sym_LPAREN] = ACTIONS(134),
    [anon_sym_RPAREN] = ACTIONS(134),
    [anon_sym_ends_with] = ACTIONS(134),
    [anon_sym_len] = ACTIONS(134),
    [anon_sym_lookup_json_string] = ACTIONS(134),
    [anon_sym_lower] = ACTIONS(134),
    [anon_sym_regex_replace] = ACTIONS(134),
    [anon_sym_remove_bytes] = ACTIONS(134),
    [anon_sym_starts_with] = ACTIONS(134),
    [anon_sym_to_string] = ACTIONS(134),
    [anon_sym_upper] = ACTIONS(134),
    [anon_sym_url_decode] = ACTIONS(134),
    [anon_sym_uuidv4] = ACTIONS(134),
    [anon_sym_not] = ACTIONS(134),
    [anon_sym_BANG] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(134),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(134),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(134),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(134),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(134),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(134),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(136),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(134),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(134),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(134),
    [anon_sym_ip_DOTsrc] = ACTIONS(136),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(134),
    [anon_sym_http_DOTcookie] = ACTIONS(134),
    [anon_sym_http_DOThost] = ACTIONS(134),
    [anon_sym_http_DOTreferer] = ACTIONS(134),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(134),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(134),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(134),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(134),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(134),
    [anon_sym_http_DOTuser_agent] = ACTIONS(134),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(134),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(134),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(134),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(134),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(134),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(134),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(134),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(134),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(134),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(134),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(134),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(134),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(136),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(134),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(134),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(134),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(134),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(134),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(134),
    [anon_sym_ssl] = ACTIONS(134),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(134),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(134),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(134),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(134),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(134),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(138),
    [anon_sym_AMP_AMP] = ACTIONS(138),
    [anon_sym_and] = ACTIONS(138),
    [anon_sym_xor] = ACTIONS(138),
    [anon_sym_CARET_CARET] = ACTIONS(138),
    [anon_sym_or] = ACTIONS(138),
    [anon_sym_PIPE_PIPE] = ACTIONS(138),
    [anon_sym_RBRACE] = ACTIONS(138),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(138),
    [anon_sym_LPAREN] = ACTIONS(138),
    [anon_sym_RPAREN] = ACTIONS(138),
    [anon_sym_ends_with] = ACTIONS(138),
    [anon_sym_len] = ACTIONS(138),
    [anon_sym_lookup_json_string] = ACTIONS(138),
    [anon_sym_lower] = ACTIONS(138),
    [anon_sym_regex_replace] = ACTIONS(138),
    [anon_sym_remove_bytes] = ACTIONS(138),
    [anon_sym_starts_with] = ACTIONS(138),
    [anon_sym_to_string] = ACTIONS(138),
    [anon_sym_upper] = ACTIONS(138),
    [anon_sym_url_decode] = ACTIONS(138),
    [anon_sym_uuidv4] = ACTIONS(138),
    [sym_ipv4] = ACTIONS(138),
    [anon_sym_SLASH] = ACTIONS(140),
    [anon_sym_not] = ACTIONS(138),
    [anon_sym_BANG] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(138),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(138),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(138),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(138),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(138),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(142),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(138),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(138),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(138),
    [anon_sym_ip_DOTsrc] = ACTIONS(142),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(138),
    [anon_sym_http_DOTcookie] = ACTIONS(138),
    [anon_sym_http_DOThost] = ACTIONS(138),
    [anon_sym_http_DOTreferer] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(138),
    [anon_sym_http_DOTuser_agent] = ACTIONS(138),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(138),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(138),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(138),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(138),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(138),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(138),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(138),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(138),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(138),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(138),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(138),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(138),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(142),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(138),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(138),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(138),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(138),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(138),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(138),
    [anon_sym_ssl] = ACTIONS(138),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(138),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(138),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(138),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(138),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(138),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(144),
    [anon_sym_AMP_AMP] = ACTIONS(144),
    [anon_sym_and] = ACTIONS(144),
    [anon_sym_xor] = ACTIONS(144),
    [anon_sym_CARET_CARET] = ACTIONS(144),
    [anon_sym_or] = ACTIONS(144),
    [anon_sym_PIPE_PIPE] = ACTIONS(144),
    [anon_sym_RBRACE] = ACTIONS(144),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(144),
    [anon_sym_LPAREN] = ACTIONS(144),
    [anon_sym_RPAREN] = ACTIONS(144),
    [anon_sym_ends_with] = ACTIONS(144),
    [anon_sym_len] = ACTIONS(144),
    [anon_sym_lookup_json_string] = ACTIONS(144),
    [anon_sym_lower] = ACTIONS(144),
    [anon_sym_regex_replace] = ACTIONS(144),
    [anon_sym_remove_bytes] = ACTIONS(144),
    [anon_sym_starts_with] = ACTIONS(144),
    [anon_sym_to_string] = ACTIONS(144),
    [anon_sym_upper] = ACTIONS(144),
    [anon_sym_url_decode] = ACTIONS(144),
    [anon_sym_uuidv4] = ACTIONS(144),
    [sym_ipv4] = ACTIONS(144),
    [anon_sym_not] = ACTIONS(144),
    [anon_sym_BANG] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(144),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(144),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(144),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(144),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(144),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(144),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(144),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(144),
    [anon_sym_ip_DOTsrc] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(144),
    [anon_sym_http_DOTcookie] = ACTIONS(144),
    [anon_sym_http_DOThost] = ACTIONS(144),
    [anon_sym_http_DOTreferer] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(144),
    [anon_sym_http_DOTuser_agent] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(144),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(144),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(144),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(144),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(144),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(144),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(144),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(144),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(144),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(144),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(144),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(144),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(144),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(144),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(144),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(144),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(144),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(144),
    [anon_sym_ssl] = ACTIONS(144),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(144),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(144),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(144),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(144),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(144),
  },
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(148),
    [anon_sym_AMP_AMP] = ACTIONS(148),
    [anon_sym_and] = ACTIONS(148),
    [anon_sym_xor] = ACTIONS(148),
    [anon_sym_CARET_CARET] = ACTIONS(148),
    [anon_sym_or] = ACTIONS(148),
    [anon_sym_PIPE_PIPE] = ACTIONS(148),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(148),
    [anon_sym_LPAREN] = ACTIONS(148),
    [anon_sym_RPAREN] = ACTIONS(148),
    [anon_sym_ends_with] = ACTIONS(148),
    [anon_sym_len] = ACTIONS(148),
    [anon_sym_lookup_json_string] = ACTIONS(148),
    [anon_sym_lower] = ACTIONS(148),
    [anon_sym_regex_replace] = ACTIONS(148),
    [anon_sym_remove_bytes] = ACTIONS(148),
    [anon_sym_starts_with] = ACTIONS(148),
    [anon_sym_to_string] = ACTIONS(148),
    [anon_sym_upper] = ACTIONS(148),
    [anon_sym_url_decode] = ACTIONS(148),
    [anon_sym_uuidv4] = ACTIONS(148),
    [anon_sym_not] = ACTIONS(148),
    [anon_sym_BANG] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(148),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(148),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(148),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(150),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(148),
    [anon_sym_ip_DOTsrc] = ACTIONS(150),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(148),
    [anon_sym_http_DOTcookie] = ACTIONS(148),
    [anon_sym_http_DOThost] = ACTIONS(148),
    [anon_sym_http_DOTreferer] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(148),
    [anon_sym_http_DOTuser_agent] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(148),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(148),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(148),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(148),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(148),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(148),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(148),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(148),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(148),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(148),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(150),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(148),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(148),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(148),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(148),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(148),
    [anon_sym_ssl] = ACTIONS(148),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(148),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(148),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(148),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(148),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(148),
  },
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(152),
    [anon_sym_AMP_AMP] = ACTIONS(152),
    [anon_sym_and] = ACTIONS(152),
    [anon_sym_xor] = ACTIONS(152),
    [anon_sym_CARET_CARET] = ACTIONS(152),
    [anon_sym_or] = ACTIONS(152),
    [anon_sym_PIPE_PIPE] = ACTIONS(152),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(152),
    [anon_sym_LPAREN] = ACTIONS(152),
    [anon_sym_RPAREN] = ACTIONS(152),
    [anon_sym_ends_with] = ACTIONS(152),
    [anon_sym_len] = ACTIONS(152),
    [anon_sym_lookup_json_string] = ACTIONS(152),
    [anon_sym_lower] = ACTIONS(152),
    [anon_sym_regex_replace] = ACTIONS(152),
    [anon_sym_remove_bytes] = ACTIONS(152),
    [anon_sym_starts_with] = ACTIONS(152),
    [anon_sym_to_string] = ACTIONS(152),
    [anon_sym_upper] = ACTIONS(152),
    [anon_sym_url_decode] = ACTIONS(152),
    [anon_sym_uuidv4] = ACTIONS(152),
    [anon_sym_not] = ACTIONS(152),
    [anon_sym_BANG] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(152),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(152),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(152),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(152),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(152),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(154),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(152),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(152),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(152),
    [anon_sym_ip_DOTsrc] = ACTIONS(154),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(152),
    [anon_sym_http_DOTcookie] = ACTIONS(152),
    [anon_sym_http_DOThost] = ACTIONS(152),
    [anon_sym_http_DOTreferer] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(152),
    [anon_sym_http_DOTuser_agent] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(152),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(152),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(152),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(152),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(152),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(152),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(152),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(152),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(152),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(152),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(152),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(152),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(154),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(152),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(152),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(152),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(152),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(152),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(152),
    [anon_sym_ssl] = ACTIONS(152),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(152),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(152),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(152),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(152),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(152),
  },
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(156),
    [anon_sym_AMP_AMP] = ACTIONS(156),
    [anon_sym_and] = ACTIONS(156),
    [anon_sym_xor] = ACTIONS(156),
    [anon_sym_CARET_CARET] = ACTIONS(156),
    [anon_sym_or] = ACTIONS(156),
    [anon_sym_PIPE_PIPE] = ACTIONS(156),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(156),
    [anon_sym_LPAREN] = ACTIONS(156),
    [anon_sym_RPAREN] = ACTIONS(156),
    [anon_sym_ends_with] = ACTIONS(156),
    [anon_sym_len] = ACTIONS(156),
    [anon_sym_lookup_json_string] = ACTIONS(156),
    [anon_sym_lower] = ACTIONS(156),
    [anon_sym_regex_replace] = ACTIONS(156),
    [anon_sym_remove_bytes] = ACTIONS(156),
    [anon_sym_starts_with] = ACTIONS(156),
    [anon_sym_to_string] = ACTIONS(156),
    [anon_sym_upper] = ACTIONS(156),
    [anon_sym_url_decode] = ACTIONS(156),
    [anon_sym_uuidv4] = ACTIONS(156),
    [anon_sym_not] = ACTIONS(156),
    [anon_sym_BANG] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(156),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(156),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(156),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(156),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(156),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(158),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(156),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(156),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(156),
    [anon_sym_ip_DOTsrc] = ACTIONS(158),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(156),
    [anon_sym_http_DOTcookie] = ACTIONS(156),
    [anon_sym_http_DOThost] = ACTIONS(156),
    [anon_sym_http_DOTreferer] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(156),
    [anon_sym_http_DOTuser_agent] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(156),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(156),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(156),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(156),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(156),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(156),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(156),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(156),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(156),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(156),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(156),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(156),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(158),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(156),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(156),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(156),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(156),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(156),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(156),
    [anon_sym_ssl] = ACTIONS(156),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(156),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(156),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(156),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(156),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(156),
  },
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(160),
    [anon_sym_AMP_AMP] = ACTIONS(160),
    [anon_sym_and] = ACTIONS(160),
    [anon_sym_xor] = ACTIONS(160),
    [anon_sym_CARET_CARET] = ACTIONS(160),
    [anon_sym_or] = ACTIONS(160),
    [anon_sym_PIPE_PIPE] = ACTIONS(160),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(160),
    [anon_sym_LPAREN] = ACTIONS(160),
    [anon_sym_RPAREN] = ACTIONS(160),
    [anon_sym_ends_with] = ACTIONS(160),
    [anon_sym_len] = ACTIONS(160),
    [anon_sym_lookup_json_string] = ACTIONS(160),
    [anon_sym_lower] = ACTIONS(160),
    [anon_sym_regex_replace] = ACTIONS(160),
    [anon_sym_remove_bytes] = ACTIONS(160),
    [anon_sym_starts_with] = ACTIONS(160),
    [anon_sym_to_string] = ACTIONS(160),
    [anon_sym_upper] = ACTIONS(160),
    [anon_sym_url_decode] = ACTIONS(160),
    [anon_sym_uuidv4] = ACTIONS(160),
    [anon_sym_not] = ACTIONS(160),
    [anon_sym_BANG] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(160),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(160),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(160),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(160),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(160),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(162),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(160),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(160),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(160),
    [anon_sym_ip_DOTsrc] = ACTIONS(162),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(160),
    [anon_sym_http_DOTcookie] = ACTIONS(160),
    [anon_sym_http_DOThost] = ACTIONS(160),
    [anon_sym_http_DOTreferer] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(160),
    [anon_sym_http_DOTuser_agent] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(160),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(160),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(160),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(160),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(160),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(160),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(160),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(160),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(160),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(160),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(160),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(160),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(162),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(160),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(160),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(160),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(160),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(160),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(160),
    [anon_sym_ssl] = ACTIONS(160),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(160),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(160),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(160),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(160),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(160),
  },
  [20] = {
    [ts_builtin_sym_end] = ACTIONS(164),
    [anon_sym_AMP_AMP] = ACTIONS(164),
    [anon_sym_and] = ACTIONS(164),
    [anon_sym_xor] = ACTIONS(164),
    [anon_sym_CARET_CARET] = ACTIONS(164),
    [anon_sym_or] = ACTIONS(164),
    [anon_sym_PIPE_PIPE] = ACTIONS(164),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(164),
    [anon_sym_LPAREN] = ACTIONS(164),
    [anon_sym_RPAREN] = ACTIONS(164),
    [anon_sym_ends_with] = ACTIONS(164),
    [anon_sym_len] = ACTIONS(164),
    [anon_sym_lookup_json_string] = ACTIONS(164),
    [anon_sym_lower] = ACTIONS(164),
    [anon_sym_regex_replace] = ACTIONS(164),
    [anon_sym_remove_bytes] = ACTIONS(164),
    [anon_sym_starts_with] = ACTIONS(164),
    [anon_sym_to_string] = ACTIONS(164),
    [anon_sym_upper] = ACTIONS(164),
    [anon_sym_url_decode] = ACTIONS(164),
    [anon_sym_uuidv4] = ACTIONS(164),
    [anon_sym_not] = ACTIONS(164),
    [anon_sym_BANG] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(164),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(164),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(164),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(164),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(164),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(166),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(164),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(164),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(164),
    [anon_sym_ip_DOTsrc] = ACTIONS(166),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(164),
    [anon_sym_http_DOTcookie] = ACTIONS(164),
    [anon_sym_http_DOThost] = ACTIONS(164),
    [anon_sym_http_DOTreferer] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(164),
    [anon_sym_http_DOTuser_agent] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(164),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(164),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(164),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(164),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(164),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(164),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(164),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(164),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(164),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(164),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(164),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(164),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(166),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(164),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(164),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(164),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(164),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(164),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(164),
    [anon_sym_ssl] = ACTIONS(164),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(164),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(164),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(164),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(164),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(164),
  },
  [21] = {
    [ts_builtin_sym_end] = ACTIONS(168),
    [anon_sym_AMP_AMP] = ACTIONS(170),
    [anon_sym_and] = ACTIONS(170),
    [anon_sym_xor] = ACTIONS(172),
    [anon_sym_CARET_CARET] = ACTIONS(172),
    [anon_sym_or] = ACTIONS(168),
    [anon_sym_PIPE_PIPE] = ACTIONS(168),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(168),
    [anon_sym_LPAREN] = ACTIONS(168),
    [anon_sym_RPAREN] = ACTIONS(168),
    [anon_sym_ends_with] = ACTIONS(168),
    [anon_sym_len] = ACTIONS(168),
    [anon_sym_lookup_json_string] = ACTIONS(168),
    [anon_sym_lower] = ACTIONS(168),
    [anon_sym_regex_replace] = ACTIONS(168),
    [anon_sym_remove_bytes] = ACTIONS(168),
    [anon_sym_starts_with] = ACTIONS(168),
    [anon_sym_to_string] = ACTIONS(168),
    [anon_sym_upper] = ACTIONS(168),
    [anon_sym_url_decode] = ACTIONS(168),
    [anon_sym_uuidv4] = ACTIONS(168),
    [anon_sym_not] = ACTIONS(168),
    [anon_sym_BANG] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(168),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(168),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(174),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(168),
    [anon_sym_ip_DOTsrc] = ACTIONS(174),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(168),
    [anon_sym_http_DOTcookie] = ACTIONS(168),
    [anon_sym_http_DOThost] = ACTIONS(168),
    [anon_sym_http_DOTreferer] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(168),
    [anon_sym_http_DOTuser_agent] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(168),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(174),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(168),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(168),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(168),
    [anon_sym_ssl] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(168),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(168),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(168),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(168),
  },
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(168),
    [anon_sym_AMP_AMP] = ACTIONS(170),
    [anon_sym_and] = ACTIONS(170),
    [anon_sym_xor] = ACTIONS(168),
    [anon_sym_CARET_CARET] = ACTIONS(168),
    [anon_sym_or] = ACTIONS(168),
    [anon_sym_PIPE_PIPE] = ACTIONS(168),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(168),
    [anon_sym_LPAREN] = ACTIONS(168),
    [anon_sym_RPAREN] = ACTIONS(168),
    [anon_sym_ends_with] = ACTIONS(168),
    [anon_sym_len] = ACTIONS(168),
    [anon_sym_lookup_json_string] = ACTIONS(168),
    [anon_sym_lower] = ACTIONS(168),
    [anon_sym_regex_replace] = ACTIONS(168),
    [anon_sym_remove_bytes] = ACTIONS(168),
    [anon_sym_starts_with] = ACTIONS(168),
    [anon_sym_to_string] = ACTIONS(168),
    [anon_sym_upper] = ACTIONS(168),
    [anon_sym_url_decode] = ACTIONS(168),
    [anon_sym_uuidv4] = ACTIONS(168),
    [anon_sym_not] = ACTIONS(168),
    [anon_sym_BANG] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(168),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(168),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(174),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(168),
    [anon_sym_ip_DOTsrc] = ACTIONS(174),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(168),
    [anon_sym_http_DOTcookie] = ACTIONS(168),
    [anon_sym_http_DOThost] = ACTIONS(168),
    [anon_sym_http_DOTreferer] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(168),
    [anon_sym_http_DOTuser_agent] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(168),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(174),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(168),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(168),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(168),
    [anon_sym_ssl] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(168),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(168),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(168),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(168),
  },
  [23] = {
    [ts_builtin_sym_end] = ACTIONS(176),
    [anon_sym_AMP_AMP] = ACTIONS(176),
    [anon_sym_and] = ACTIONS(176),
    [anon_sym_xor] = ACTIONS(176),
    [anon_sym_CARET_CARET] = ACTIONS(176),
    [anon_sym_or] = ACTIONS(176),
    [anon_sym_PIPE_PIPE] = ACTIONS(176),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(176),
    [anon_sym_LPAREN] = ACTIONS(176),
    [anon_sym_RPAREN] = ACTIONS(176),
    [anon_sym_ends_with] = ACTIONS(176),
    [anon_sym_len] = ACTIONS(176),
    [anon_sym_lookup_json_string] = ACTIONS(176),
    [anon_sym_lower] = ACTIONS(176),
    [anon_sym_regex_replace] = ACTIONS(176),
    [anon_sym_remove_bytes] = ACTIONS(176),
    [anon_sym_starts_with] = ACTIONS(176),
    [anon_sym_to_string] = ACTIONS(176),
    [anon_sym_upper] = ACTIONS(176),
    [anon_sym_url_decode] = ACTIONS(176),
    [anon_sym_uuidv4] = ACTIONS(176),
    [anon_sym_not] = ACTIONS(176),
    [anon_sym_BANG] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(176),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(176),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(176),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(176),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(176),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(178),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(176),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(176),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(176),
    [anon_sym_ip_DOTsrc] = ACTIONS(178),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(176),
    [anon_sym_http_DOTcookie] = ACTIONS(176),
    [anon_sym_http_DOThost] = ACTIONS(176),
    [anon_sym_http_DOTreferer] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(178),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(176),
    [anon_sym_http_DOTuser_agent] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(176),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(176),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(176),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(176),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(176),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(176),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(176),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(176),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(176),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(176),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(176),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(176),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(178),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(176),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(176),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(176),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(176),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(176),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(176),
    [anon_sym_ssl] = ACTIONS(176),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(176),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(176),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(176),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(176),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(176),
  },
  [24] = {
    [ts_builtin_sym_end] = ACTIONS(168),
    [anon_sym_AMP_AMP] = ACTIONS(168),
    [anon_sym_and] = ACTIONS(168),
    [anon_sym_xor] = ACTIONS(168),
    [anon_sym_CARET_CARET] = ACTIONS(168),
    [anon_sym_or] = ACTIONS(168),
    [anon_sym_PIPE_PIPE] = ACTIONS(168),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(168),
    [anon_sym_LPAREN] = ACTIONS(168),
    [anon_sym_RPAREN] = ACTIONS(168),
    [anon_sym_ends_with] = ACTIONS(168),
    [anon_sym_len] = ACTIONS(168),
    [anon_sym_lookup_json_string] = ACTIONS(168),
    [anon_sym_lower] = ACTIONS(168),
    [anon_sym_regex_replace] = ACTIONS(168),
    [anon_sym_remove_bytes] = ACTIONS(168),
    [anon_sym_starts_with] = ACTIONS(168),
    [anon_sym_to_string] = ACTIONS(168),
    [anon_sym_upper] = ACTIONS(168),
    [anon_sym_url_decode] = ACTIONS(168),
    [anon_sym_uuidv4] = ACTIONS(168),
    [anon_sym_not] = ACTIONS(168),
    [anon_sym_BANG] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(168),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(168),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(174),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(168),
    [anon_sym_ip_DOTsrc] = ACTIONS(174),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(168),
    [anon_sym_http_DOTcookie] = ACTIONS(168),
    [anon_sym_http_DOThost] = ACTIONS(168),
    [anon_sym_http_DOTreferer] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(168),
    [anon_sym_http_DOTuser_agent] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(168),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(168),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(174),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(168),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(168),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(168),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(168),
    [anon_sym_ssl] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(168),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(168),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(168),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(168),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(168),
  },
  [25] = {
    [ts_builtin_sym_end] = ACTIONS(180),
    [anon_sym_AMP_AMP] = ACTIONS(180),
    [anon_sym_and] = ACTIONS(180),
    [anon_sym_xor] = ACTIONS(180),
    [anon_sym_CARET_CARET] = ACTIONS(180),
    [anon_sym_or] = ACTIONS(180),
    [anon_sym_PIPE_PIPE] = ACTIONS(180),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(180),
    [anon_sym_LPAREN] = ACTIONS(180),
    [anon_sym_RPAREN] = ACTIONS(180),
    [anon_sym_ends_with] = ACTIONS(180),
    [anon_sym_len] = ACTIONS(180),
    [anon_sym_lookup_json_string] = ACTIONS(180),
    [anon_sym_lower] = ACTIONS(180),
    [anon_sym_regex_replace] = ACTIONS(180),
    [anon_sym_remove_bytes] = ACTIONS(180),
    [anon_sym_starts_with] = ACTIONS(180),
    [anon_sym_to_string] = ACTIONS(180),
    [anon_sym_upper] = ACTIONS(180),
    [anon_sym_url_decode] = ACTIONS(180),
    [anon_sym_uuidv4] = ACTIONS(180),
    [anon_sym_not] = ACTIONS(180),
    [anon_sym_BANG] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(180),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(180),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(180),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(180),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(180),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(182),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(180),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(180),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(180),
    [anon_sym_ip_DOTsrc] = ACTIONS(182),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(180),
    [anon_sym_http_DOTcookie] = ACTIONS(180),
    [anon_sym_http_DOThost] = ACTIONS(180),
    [anon_sym_http_DOTreferer] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(180),
    [anon_sym_http_DOTuser_agent] = ACTIONS(180),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(180),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(180),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(180),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(180),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(180),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(180),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(180),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(180),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(180),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(180),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(180),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(180),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(182),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(180),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(180),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(180),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(180),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(180),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(180),
    [anon_sym_ssl] = ACTIONS(180),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(180),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(180),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(180),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(180),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(180),
  },
  [26] = {
    [ts_builtin_sym_end] = ACTIONS(184),
    [anon_sym_AMP_AMP] = ACTIONS(184),
    [anon_sym_and] = ACTIONS(184),
    [anon_sym_xor] = ACTIONS(184),
    [anon_sym_CARET_CARET] = ACTIONS(184),
    [anon_sym_or] = ACTIONS(184),
    [anon_sym_PIPE_PIPE] = ACTIONS(184),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(184),
    [anon_sym_LPAREN] = ACTIONS(184),
    [anon_sym_RPAREN] = ACTIONS(184),
    [anon_sym_ends_with] = ACTIONS(184),
    [anon_sym_len] = ACTIONS(184),
    [anon_sym_lookup_json_string] = ACTIONS(184),
    [anon_sym_lower] = ACTIONS(184),
    [anon_sym_regex_replace] = ACTIONS(184),
    [anon_sym_remove_bytes] = ACTIONS(184),
    [anon_sym_starts_with] = ACTIONS(184),
    [anon_sym_to_string] = ACTIONS(184),
    [anon_sym_upper] = ACTIONS(184),
    [anon_sym_url_decode] = ACTIONS(184),
    [anon_sym_uuidv4] = ACTIONS(184),
    [anon_sym_not] = ACTIONS(184),
    [anon_sym_BANG] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(184),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(184),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(184),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(184),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(184),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(186),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(184),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(184),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(184),
    [anon_sym_ip_DOTsrc] = ACTIONS(186),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(184),
    [anon_sym_http_DOTcookie] = ACTIONS(184),
    [anon_sym_http_DOThost] = ACTIONS(184),
    [anon_sym_http_DOTreferer] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(184),
    [anon_sym_http_DOTuser_agent] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(184),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(184),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(184),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(184),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(184),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(184),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(184),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(184),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(184),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(184),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(184),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(184),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(186),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(184),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(184),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(184),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(184),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(184),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(184),
    [anon_sym_ssl] = ACTIONS(184),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(184),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(184),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(184),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(184),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(184),
  },
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(188),
    [anon_sym_AMP_AMP] = ACTIONS(170),
    [anon_sym_and] = ACTIONS(170),
    [anon_sym_xor] = ACTIONS(172),
    [anon_sym_CARET_CARET] = ACTIONS(172),
    [anon_sym_or] = ACTIONS(190),
    [anon_sym_PIPE_PIPE] = ACTIONS(190),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(188),
    [anon_sym_LPAREN] = ACTIONS(188),
    [anon_sym_ends_with] = ACTIONS(188),
    [anon_sym_len] = ACTIONS(188),
    [anon_sym_lookup_json_string] = ACTIONS(188),
    [anon_sym_lower] = ACTIONS(188),
    [anon_sym_regex_replace] = ACTIONS(188),
    [anon_sym_remove_bytes] = ACTIONS(188),
    [anon_sym_starts_with] = ACTIONS(188),
    [anon_sym_to_string] = ACTIONS(188),
    [anon_sym_upper] = ACTIONS(188),
    [anon_sym_url_decode] = ACTIONS(188),
    [anon_sym_uuidv4] = ACTIONS(188),
    [anon_sym_not] = ACTIONS(188),
    [anon_sym_BANG] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(188),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(188),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(188),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(188),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(188),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(192),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(188),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(188),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(188),
    [anon_sym_ip_DOTsrc] = ACTIONS(192),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(188),
    [anon_sym_http_DOTcookie] = ACTIONS(188),
    [anon_sym_http_DOThost] = ACTIONS(188),
    [anon_sym_http_DOTreferer] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(192),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(188),
    [anon_sym_http_DOTuser_agent] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(188),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(188),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(188),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(188),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(188),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(188),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(188),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(188),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(188),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(188),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(188),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(188),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(192),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(188),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(188),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(188),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(188),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(188),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(188),
    [anon_sym_ssl] = ACTIONS(188),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(188),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(188),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(188),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(188),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(188),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(196), 4,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_ip_DOTsrc,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(194), 58,
      anon_sym_concat,
      anon_sym_LPAREN,
      anon_sym_ends_with,
      anon_sym_len,
      anon_sym_lookup_json_string,
      anon_sym_lower,
      anon_sym_regex_replace,
      anon_sym_remove_bytes,
      anon_sym_starts_with,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_uuidv4,
      anon_sym_not,
      anon_sym_BANG,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
      anon_sym_ip_DOTgeoip_DOTasnum,
      anon_sym_cf_DOTbot_management_DOTscore,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTthreat_score,
      anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
      anon_sym_cf_DOTwaf_DOTscore_DOTxss,
      anon_sym_cf_DOTwaf_DOTscore_DOTrce,
      anon_sym_cf_DOTedge_DOTserver_ip,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
  [70] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(200), 4,
      anon_sym_LT,
      anon_sym_GT,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(198), 44,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [126] = 7,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(202), 1,
      anon_sym_RPAREN,
    ACTIONS(204), 1,
      sym_string,
    STATE(31), 1,
      aux_sym_concat_func_repeat1,
    STATE(35), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [174] = 7,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(206), 1,
      anon_sym_RPAREN,
    ACTIONS(208), 1,
      sym_string,
    STATE(31), 1,
      aux_sym_concat_func_repeat1,
    STATE(35), 1,
      sym_string_field,
    ACTIONS(214), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(211), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [222] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(217), 1,
      anon_sym_cf_DOTrandom_seed,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(87), 2,
      sym_string_field,
      sym_bytes_field,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [265] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(217), 1,
      anon_sym_cf_DOTrandom_seed,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(109), 2,
      sym_string_field,
      sym_bytes_field,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [308] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(204), 1,
      sym_string,
    STATE(30), 1,
      aux_sym_concat_func_repeat1,
    STATE(35), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [353] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(219), 1,
      anon_sym_COMMA,
    ACTIONS(223), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(221), 28,
      anon_sym_RPAREN,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [394] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(225), 1,
      sym_string,
    STATE(94), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [436] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(227), 1,
      sym_string,
    STATE(121), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [478] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(229), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(206), 28,
      anon_sym_RPAREN,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [516] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(93), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [555] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(70), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [594] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(95), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [633] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(107), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [672] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(85), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [711] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(100), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 26,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTuri_DOTpath,
      anon_sym_http_DOTrequest_DOTuri_DOTquery,
      anon_sym_http_DOTuser_agent,
      anon_sym_http_DOTrequest_DOTversion,
      anon_sym_http_DOTx_forwarded_for,
      anon_sym_ip_DOTsrc_DOTlat,
      anon_sym_ip_DOTsrc_DOTlon,
      anon_sym_ip_DOTsrc_DOTcity,
      anon_sym_ip_DOTsrc_DOTpostal_code,
      anon_sym_ip_DOTsrc_DOTmetro_code,
      anon_sym_ip_DOTgeoip_DOTcontinent,
      anon_sym_ip_DOTgeoip_DOTcountry,
      anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
      anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
      anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
      anon_sym_cf_DOTbot_management_DOTja3_hash,
      anon_sym_cf_DOThostname_DOTmetadata,
      anon_sym_cf_DOTworker_DOTupstream_zone,
  [750] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(37), 1,
      anon_sym_cf_DOTwaf_DOTscore,
    ACTIONS(41), 2,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
    STATE(101), 3,
      sym_number_field,
      sym_ip_field,
      sym_boolean_field,
    ACTIONS(47), 7,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
    ACTIONS(35), 9,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
      anon_sym_ip_DOTgeoip_DOTasnum,
      anon_sym_cf_DOTbot_management_DOTscore,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTthreat_score,
      anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
      anon_sym_cf_DOTwaf_DOTscore_DOTxss,
      anon_sym_cf_DOTwaf_DOTscore_DOTrce,
  [786] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(233), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(231), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [810] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(235), 1,
      anon_sym_in,
    ACTIONS(239), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(237), 13,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [836] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(243), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(241), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [860] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(247), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(245), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [884] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(251), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(249), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [908] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(255), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(253), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [932] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(259), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(257), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [956] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(263), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(261), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [980] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(267), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(265), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1004] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(271), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(269), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1028] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(275), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(273), 14,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_contains,
      anon_sym_matches,
      anon_sym_TILDE,
  [1052] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(279), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(277), 12,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
      anon_sym_RPAREN,
  [1074] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(281), 1,
      anon_sym_in,
    ACTIONS(285), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(283), 10,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
  [1097] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(289), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(287), 11,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
  [1118] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(293), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(291), 11,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
      anon_sym_le,
      anon_sym_gt,
      anon_sym_ge,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_LT_EQ,
      anon_sym_GT_EQ,
  [1139] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(295), 1,
      anon_sym_RPAREN,
    ACTIONS(170), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(172), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(190), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [1158] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(297), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [1170] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(299), 1,
      anon_sym_RBRACE,
    ACTIONS(301), 1,
      sym_ipv4,
    STATE(63), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1185] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(304), 1,
      anon_sym_in,
    ACTIONS(306), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [1198] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(308), 1,
      anon_sym_RBRACE,
    ACTIONS(310), 1,
      sym_ipv4,
    STATE(63), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1213] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(312), 1,
      anon_sym_RPAREN,
    STATE(66), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(314), 2,
      sym_number,
      sym_string,
  [1227] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(317), 1,
      anon_sym_RPAREN,
    STATE(66), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(319), 2,
      sym_number,
      sym_string,
  [1241] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(310), 1,
      sym_ipv4,
    STATE(65), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1253] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(321), 1,
      anon_sym_COMMA,
    ACTIONS(323), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1265] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(67), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(319), 2,
      sym_number,
      sym_string,
  [1276] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_boolean,
    ACTIONS(325), 2,
      anon_sym_true,
      anon_sym_false,
  [1287] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(327), 1,
      anon_sym_RBRACE,
    ACTIONS(329), 1,
      sym_string,
    STATE(72), 1,
      aux_sym_string_set_repeat1,
  [1300] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(332), 1,
      anon_sym_RBRACE,
    ACTIONS(334), 1,
      sym_number,
    STATE(73), 1,
      aux_sym_number_set_repeat1,
  [1313] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(337), 1,
      anon_sym_LBRACE,
    ACTIONS(339), 1,
      sym_ip_list,
    STATE(17), 1,
      sym_ip_set,
  [1326] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(312), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1335] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(310), 1,
      sym_ipv4,
    STATE(19), 2,
      sym__ip,
      sym_ip_range,
  [1346] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(341), 1,
      anon_sym_RBRACE,
    ACTIONS(343), 1,
      sym_number,
    STATE(73), 1,
      aux_sym_number_set_repeat1,
  [1359] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(345), 1,
      anon_sym_RBRACE,
    ACTIONS(347), 1,
      sym_string,
    STATE(72), 1,
      aux_sym_string_set_repeat1,
  [1372] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(349), 1,
      sym_string,
    STATE(78), 1,
      aux_sym_string_set_repeat1,
  [1382] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(217), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(111), 1,
      sym_bytes_field,
  [1392] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(351), 1,
      anon_sym_LBRACE,
    STATE(17), 1,
      sym_number_set,
  [1402] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(353), 1,
      anon_sym_LBRACE,
    STATE(17), 1,
      sym_string_set,
  [1412] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(355), 1,
      sym_number,
    STATE(77), 1,
      aux_sym_number_set_repeat1,
  [1422] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(357), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [1430] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(359), 1,
      anon_sym_RPAREN,
  [1437] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(361), 1,
      anon_sym_RPAREN,
  [1444] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(363), 1,
      anon_sym_RPAREN,
  [1451] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(365), 1,
      sym_string,
  [1458] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(367), 1,
      sym_string,
  [1465] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(369), 1,
      sym_string,
  [1472] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(371), 1,
      sym_string,
  [1479] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(373), 1,
      anon_sym_LPAREN,
  [1486] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(375), 1,
      anon_sym_COMMA,
  [1493] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(377), 1,
      anon_sym_COMMA,
  [1500] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(379), 1,
      anon_sym_RPAREN,
  [1507] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(381), 1,
      aux_sym_ip_range_token1,
  [1514] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(383), 1,
      anon_sym_LPAREN,
  [1521] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(385), 1,
      anon_sym_LPAREN,
  [1528] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(387), 1,
      anon_sym_RPAREN,
  [1535] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(389), 1,
      anon_sym_RPAREN,
  [1542] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(391), 1,
      anon_sym_RPAREN,
  [1549] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(393), 1,
      sym_string,
  [1556] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(395), 1,
      anon_sym_COMMA,
  [1563] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(397), 1,
      ts_builtin_sym_end,
  [1570] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(399), 1,
      anon_sym_RPAREN,
  [1577] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(401), 1,
      anon_sym_LPAREN,
  [1584] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(403), 1,
      anon_sym_COMMA,
  [1591] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(405), 1,
      anon_sym_LPAREN,
  [1598] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(407), 1,
      anon_sym_COMMA,
  [1605] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 1,
      anon_sym_LPAREN,
  [1612] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(411), 1,
      anon_sym_RPAREN,
  [1619] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(413), 1,
      anon_sym_LPAREN,
  [1626] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(415), 1,
      anon_sym_LPAREN,
  [1633] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(393), 1,
      sym_number,
  [1640] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(417), 1,
      anon_sym_LPAREN,
  [1647] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(419), 1,
      anon_sym_LPAREN,
  [1654] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(421), 1,
      sym_string,
  [1661] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(423), 1,
      anon_sym_LPAREN,
  [1668] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(425), 1,
      anon_sym_LPAREN,
  [1675] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(427), 1,
      anon_sym_RPAREN,
  [1682] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(429), 1,
      anon_sym_COMMA,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(28)] = 0,
  [SMALL_STATE(29)] = 70,
  [SMALL_STATE(30)] = 126,
  [SMALL_STATE(31)] = 174,
  [SMALL_STATE(32)] = 222,
  [SMALL_STATE(33)] = 265,
  [SMALL_STATE(34)] = 308,
  [SMALL_STATE(35)] = 353,
  [SMALL_STATE(36)] = 394,
  [SMALL_STATE(37)] = 436,
  [SMALL_STATE(38)] = 478,
  [SMALL_STATE(39)] = 516,
  [SMALL_STATE(40)] = 555,
  [SMALL_STATE(41)] = 594,
  [SMALL_STATE(42)] = 633,
  [SMALL_STATE(43)] = 672,
  [SMALL_STATE(44)] = 711,
  [SMALL_STATE(45)] = 750,
  [SMALL_STATE(46)] = 786,
  [SMALL_STATE(47)] = 810,
  [SMALL_STATE(48)] = 836,
  [SMALL_STATE(49)] = 860,
  [SMALL_STATE(50)] = 884,
  [SMALL_STATE(51)] = 908,
  [SMALL_STATE(52)] = 932,
  [SMALL_STATE(53)] = 956,
  [SMALL_STATE(54)] = 980,
  [SMALL_STATE(55)] = 1004,
  [SMALL_STATE(56)] = 1028,
  [SMALL_STATE(57)] = 1052,
  [SMALL_STATE(58)] = 1074,
  [SMALL_STATE(59)] = 1097,
  [SMALL_STATE(60)] = 1118,
  [SMALL_STATE(61)] = 1139,
  [SMALL_STATE(62)] = 1158,
  [SMALL_STATE(63)] = 1170,
  [SMALL_STATE(64)] = 1185,
  [SMALL_STATE(65)] = 1198,
  [SMALL_STATE(66)] = 1213,
  [SMALL_STATE(67)] = 1227,
  [SMALL_STATE(68)] = 1241,
  [SMALL_STATE(69)] = 1253,
  [SMALL_STATE(70)] = 1265,
  [SMALL_STATE(71)] = 1276,
  [SMALL_STATE(72)] = 1287,
  [SMALL_STATE(73)] = 1300,
  [SMALL_STATE(74)] = 1313,
  [SMALL_STATE(75)] = 1326,
  [SMALL_STATE(76)] = 1335,
  [SMALL_STATE(77)] = 1346,
  [SMALL_STATE(78)] = 1359,
  [SMALL_STATE(79)] = 1372,
  [SMALL_STATE(80)] = 1382,
  [SMALL_STATE(81)] = 1392,
  [SMALL_STATE(82)] = 1402,
  [SMALL_STATE(83)] = 1412,
  [SMALL_STATE(84)] = 1422,
  [SMALL_STATE(85)] = 1430,
  [SMALL_STATE(86)] = 1437,
  [SMALL_STATE(87)] = 1444,
  [SMALL_STATE(88)] = 1451,
  [SMALL_STATE(89)] = 1458,
  [SMALL_STATE(90)] = 1465,
  [SMALL_STATE(91)] = 1472,
  [SMALL_STATE(92)] = 1479,
  [SMALL_STATE(93)] = 1486,
  [SMALL_STATE(94)] = 1493,
  [SMALL_STATE(95)] = 1500,
  [SMALL_STATE(96)] = 1507,
  [SMALL_STATE(97)] = 1514,
  [SMALL_STATE(98)] = 1521,
  [SMALL_STATE(99)] = 1528,
  [SMALL_STATE(100)] = 1535,
  [SMALL_STATE(101)] = 1542,
  [SMALL_STATE(102)] = 1549,
  [SMALL_STATE(103)] = 1556,
  [SMALL_STATE(104)] = 1563,
  [SMALL_STATE(105)] = 1570,
  [SMALL_STATE(106)] = 1577,
  [SMALL_STATE(107)] = 1584,
  [SMALL_STATE(108)] = 1591,
  [SMALL_STATE(109)] = 1598,
  [SMALL_STATE(110)] = 1605,
  [SMALL_STATE(111)] = 1612,
  [SMALL_STATE(112)] = 1619,
  [SMALL_STATE(113)] = 1626,
  [SMALL_STATE(114)] = 1633,
  [SMALL_STATE(115)] = 1640,
  [SMALL_STATE(116)] = 1647,
  [SMALL_STATE(117)] = 1654,
  [SMALL_STATE(118)] = 1661,
  [SMALL_STATE(119)] = 1668,
  [SMALL_STATE(120)] = 1675,
  [SMALL_STATE(121)] = 1682,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(118),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(4),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(119),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(113),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(110),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(106),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(98),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(97),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(92),
  [33] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [35] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [37] = {.entry = {.count = 1, .reusable = false}}, SHIFT(57),
  [39] = {.entry = {.count = 1, .reusable = false}}, SHIFT(62),
  [41] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [43] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [45] = {.entry = {.count = 1, .reusable = false}}, SHIFT(29),
  [47] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [49] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [51] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(118),
  [54] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(4),
  [57] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(119),
  [60] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(116),
  [63] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(115),
  [66] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(113),
  [69] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(112),
  [72] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(110),
  [75] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(108),
  [78] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(106),
  [81] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(98),
  [84] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(97),
  [87] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(92),
  [90] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(28),
  [93] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(57),
  [96] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(57),
  [99] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(62),
  [102] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(62),
  [105] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(29),
  [108] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(29),
  [111] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(13),
  [114] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [116] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_starts_with_func, 6, .production_id = 6),
  [118] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_starts_with_func, 6, .production_id = 6),
  [120] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ends_with_func, 6, .production_id = 6),
  [122] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ends_with_func, 6, .production_id = 6),
  [124] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 1),
  [126] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 1),
  [128] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__expression, 1),
  [130] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [132] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__expression, 1),
  [134] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean_field, 1),
  [136] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean_field, 1),
  [138] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [140] = {.entry = {.count = 1, .reusable = true}}, SHIFT(96),
  [142] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [144] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 5),
  [146] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 5),
  [148] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3),
  [150] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3),
  [152] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 1),
  [154] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 1),
  [156] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [158] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [160] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 1),
  [162] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 1),
  [164] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [166] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [168] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 1),
  [170] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [172] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [174] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 1),
  [176] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [178] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [180] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [182] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [184] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [186] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [188] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [190] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [192] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [194] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [196] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [198] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [200] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [202] = {.entry = {.count = 1, .reusable = true}}, SHIFT(50),
  [204] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [206] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 2),
  [208] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 2), SHIFT_REPEAT(35),
  [211] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 2), SHIFT_REPEAT(29),
  [214] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_concat_func_repeat1, 2), SHIFT_REPEAT(29),
  [217] = {.entry = {.count = 1, .reusable = true}}, SHIFT(84),
  [219] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [221] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 1),
  [223] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_concat_func_repeat1, 1),
  [225] = {.entry = {.count = 1, .reusable = true}}, SHIFT(94),
  [227] = {.entry = {.count = 1, .reusable = true}}, SHIFT(121),
  [229] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_concat_func_repeat1, 2),
  [231] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_upper_func, 4, .production_id = 2),
  [233] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_upper_func, 4, .production_id = 2),
  [235] = {.entry = {.count = 1, .reusable = true}}, SHIFT(82),
  [237] = {.entry = {.count = 1, .reusable = true}}, SHIFT(102),
  [239] = {.entry = {.count = 1, .reusable = false}}, SHIFT(102),
  [241] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_regex_replace_func, 8, .production_id = 8),
  [243] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_regex_replace_func, 8, .production_id = 8),
  [245] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 7),
  [247] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 7),
  [249] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_concat_func, 6),
  [251] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_concat_func, 6),
  [253] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_lookup_func, 5, .production_id = 4),
  [255] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_lookup_func, 5, .production_id = 4),
  [257] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_uuid_func, 4, .production_id = 3),
  [259] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_uuid_func, 4, .production_id = 3),
  [261] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_url_decode_func, 4, .production_id = 2),
  [263] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_url_decode_func, 4, .production_id = 2),
  [265] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_to_string_func, 4, .production_id = 2),
  [267] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_to_string_func, 4, .production_id = 2),
  [269] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_lower_func, 4, .production_id = 2),
  [271] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_lower_func, 4, .production_id = 2),
  [273] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 1),
  [275] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 1),
  [277] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [279] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [281] = {.entry = {.count = 1, .reusable = true}}, SHIFT(81),
  [283] = {.entry = {.count = 1, .reusable = true}}, SHIFT(114),
  [285] = {.entry = {.count = 1, .reusable = false}}, SHIFT(114),
  [287] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_len_func, 4, .production_id = 2),
  [289] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_len_func, 4, .production_id = 2),
  [291] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 1),
  [293] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 1),
  [295] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [297] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [299] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [301] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(14),
  [304] = {.entry = {.count = 1, .reusable = true}}, SHIFT(74),
  [306] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [308] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [310] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [312] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 2),
  [314] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 2), SHIFT_REPEAT(69),
  [317] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [319] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [321] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [323] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 1),
  [325] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [327] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [329] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(72),
  [332] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [334] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(73),
  [337] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [339] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [341] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [343] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [345] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [347] = {.entry = {.count = 1, .reusable = true}}, SHIFT(72),
  [349] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [351] = {.entry = {.count = 1, .reusable = true}}, SHIFT(83),
  [353] = {.entry = {.count = 1, .reusable = true}}, SHIFT(79),
  [355] = {.entry = {.count = 1, .reusable = true}}, SHIFT(77),
  [357] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [359] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [361] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [363] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [365] = {.entry = {.count = 1, .reusable = true}}, SHIFT(99),
  [367] = {.entry = {.count = 1, .reusable = true}}, SHIFT(103),
  [369] = {.entry = {.count = 1, .reusable = true}}, SHIFT(86),
  [371] = {.entry = {.count = 1, .reusable = true}}, SHIFT(105),
  [373] = {.entry = {.count = 1, .reusable = true}}, SHIFT(80),
  [375] = {.entry = {.count = 1, .reusable = true}}, SHIFT(88),
  [377] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [379] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [381] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [383] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [385] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [387] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [389] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [391] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [393] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [395] = {.entry = {.count = 1, .reusable = true}}, SHIFT(117),
  [397] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [399] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [401] = {.entry = {.count = 1, .reusable = true}}, SHIFT(45),
  [403] = {.entry = {.count = 1, .reusable = true}}, SHIFT(91),
  [405] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [407] = {.entry = {.count = 1, .reusable = true}}, SHIFT(90),
  [409] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [411] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [413] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [415] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [417] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [419] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [421] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [423] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [425] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [427] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [429] = {.entry = {.count = 1, .reusable = true}}, SHIFT(89),
};

#ifdef __cplusplus
extern "C" {
#endif
#ifdef _WIN32
#define extern __declspec(dllexport)
#endif

extern const TSLanguage *tree_sitter_cloudflare(void) {
  static const TSLanguage language = {
    .version = LANGUAGE_VERSION,
    .symbol_count = SYMBOL_COUNT,
    .alias_count = ALIAS_COUNT,
    .token_count = TOKEN_COUNT,
    .external_token_count = EXTERNAL_TOKEN_COUNT,
    .state_count = STATE_COUNT,
    .large_state_count = LARGE_STATE_COUNT,
    .production_id_count = PRODUCTION_ID_COUNT,
    .field_count = FIELD_COUNT,
    .max_alias_sequence_length = MAX_ALIAS_SEQUENCE_LENGTH,
    .parse_table = &ts_parse_table[0][0],
    .small_parse_table = ts_small_parse_table,
    .small_parse_table_map = ts_small_parse_table_map,
    .parse_actions = ts_parse_actions,
    .symbol_names = ts_symbol_names,
    .field_names = ts_field_names,
    .field_map_slices = ts_field_map_slices,
    .field_map_entries = ts_field_map_entries,
    .symbol_metadata = ts_symbol_metadata,
    .public_symbol_map = ts_symbol_map,
    .alias_map = ts_non_terminal_alias_map,
    .alias_sequences = &ts_alias_sequences[0][0],
    .lex_modes = ts_lex_modes,
    .lex_fn = ts_lex,
    .primary_state_ids = ts_primary_state_ids,
  };
  return &language;
}
#ifdef __cplusplus
}
#endif
