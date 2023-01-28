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
#define STATE_COUNT 312
#define LARGE_STATE_COUNT 64
#define SYMBOL_COUNT 150
#define ALIAS_COUNT 0
#define TOKEN_COUNT 110
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 16
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 22

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
  anon_sym_lookup_json_string = 30,
  anon_sym_lower = 31,
  anon_sym_regex_replace = 32,
  anon_sym_remove_bytes = 33,
  anon_sym_to_string = 34,
  anon_sym_upper = 35,
  anon_sym_url_decode = 36,
  anon_sym_uuidv4 = 37,
  anon_sym_len = 38,
  anon_sym_ends_with = 39,
  anon_sym_starts_with = 40,
  anon_sym_any = 41,
  anon_sym_all = 42,
  anon_sym_LBRACK_STAR_RBRACK = 43,
  sym_number = 44,
  sym_string = 45,
  anon_sym_true = 46,
  anon_sym_false = 47,
  sym_ipv4 = 48,
  anon_sym_SLASH = 49,
  aux_sym_ip_range_token1 = 50,
  sym_ip_list = 51,
  anon_sym_not = 52,
  anon_sym_BANG = 53,
  anon_sym_LBRACK = 54,
  anon_sym_RBRACK = 55,
  anon_sym_STAR = 56,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTsec = 57,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec = 58,
  anon_sym_ip_DOTgeoip_DOTasnum = 59,
  anon_sym_cf_DOTbot_management_DOTscore = 60,
  anon_sym_cf_DOTedge_DOTserver_port = 61,
  anon_sym_cf_DOTthreat_score = 62,
  anon_sym_cf_DOTwaf_DOTscore = 63,
  anon_sym_cf_DOTwaf_DOTscore_DOTsqli = 64,
  anon_sym_cf_DOTwaf_DOTscore_DOTxss = 65,
  anon_sym_cf_DOTwaf_DOTscore_DOTrce = 66,
  anon_sym_ip_DOTsrc = 67,
  anon_sym_cf_DOTedge_DOTserver_ip = 68,
  anon_sym_http_DOTcookie = 69,
  anon_sym_http_DOThost = 70,
  anon_sym_http_DOTreferer = 71,
  anon_sym_http_DOTrequest_DOTfull_uri = 72,
  anon_sym_http_DOTrequest_DOTmethod = 73,
  anon_sym_http_DOTrequest_DOTuri = 74,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 75,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 76,
  anon_sym_http_DOTuser_agent = 77,
  anon_sym_http_DOTrequest_DOTversion = 78,
  anon_sym_http_DOTx_forwarded_for = 79,
  anon_sym_ip_DOTsrc_DOTlat = 80,
  anon_sym_ip_DOTsrc_DOTlon = 81,
  anon_sym_ip_DOTsrc_DOTcity = 82,
  anon_sym_ip_DOTsrc_DOTpostal_code = 83,
  anon_sym_ip_DOTsrc_DOTmetro_code = 84,
  anon_sym_ip_DOTgeoip_DOTcontinent = 85,
  anon_sym_ip_DOTgeoip_DOTcountry = 86,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 87,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 88,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 89,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 90,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 91,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 92,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 93,
  anon_sym_cf_DOThostname_DOTmetadata = 94,
  anon_sym_cf_DOTworker_DOTupstream_zone = 95,
  anon_sym_cf_DOTrandom_seed = 96,
  anon_sym_http_DOTrequest_DOTcookies = 97,
  anon_sym_http_DOTrequest_DOTheaders = 98,
  anon_sym_http_DOTrequest_DOTheaders_DOTnames = 99,
  anon_sym_http_DOTrequest_DOTheaders_DOTvalues = 100,
  anon_sym_http_DOTrequest_DOTaccepted_languages = 101,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 102,
  anon_sym_ssl = 103,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 104,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 105,
  anon_sym_cf_DOTclient_DOTbot = 106,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 107,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 108,
  anon_sym_http_DOTrequest_DOTheaders_DOTtruncated = 109,
  sym_source_file = 110,
  sym__expression = 111,
  sym_not_expression = 112,
  sym_in_expression = 113,
  sym_compound_expression = 114,
  sym_ip_set = 115,
  sym_string_set = 116,
  sym_number_set = 117,
  sym_simple_expression = 118,
  sym__bool_lhs = 119,
  sym__number_lhs = 120,
  sym__string_lhs = 121,
  sym_string_func = 122,
  sym_number_func = 123,
  sym_bool_func = 124,
  sym_group = 125,
  sym_boolean = 126,
  sym__ip = 127,
  sym_ip_range = 128,
  sym_not_operator = 129,
  sym__number_array = 130,
  sym__bool_array = 131,
  sym__string_array = 132,
  sym__string_array_expansion = 133,
  sym__boollike_field = 134,
  sym__numberlike_field = 135,
  sym__stringlike_field = 136,
  sym_number_field = 137,
  sym_ip_field = 138,
  sym_string_field = 139,
  sym_bytes_field = 140,
  sym_map_string_array_field = 141,
  sym_array_string_field = 142,
  sym_bool_field = 143,
  aux_sym_source_file_repeat1 = 144,
  aux_sym_ip_set_repeat1 = 145,
  aux_sym_string_set_repeat1 = 146,
  aux_sym_number_set_repeat1 = 147,
  aux_sym_string_func_repeat1 = 148,
  aux_sym_string_func_repeat2 = 149,
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
  [anon_sym_lookup_json_string] = "lookup_json_string",
  [anon_sym_lower] = "lower",
  [anon_sym_regex_replace] = "regex_replace",
  [anon_sym_remove_bytes] = "remove_bytes",
  [anon_sym_to_string] = "to_string",
  [anon_sym_upper] = "upper",
  [anon_sym_url_decode] = "url_decode",
  [anon_sym_uuidv4] = "uuidv4",
  [anon_sym_len] = "len",
  [anon_sym_ends_with] = "ends_with",
  [anon_sym_starts_with] = "starts_with",
  [anon_sym_any] = "any",
  [anon_sym_all] = "all",
  [anon_sym_LBRACK_STAR_RBRACK] = "[*]",
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
  [anon_sym_LBRACK] = "[",
  [anon_sym_RBRACK] = "]",
  [anon_sym_STAR] = "*",
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
  [anon_sym_http_DOTrequest_DOTcookies] = "http.request.cookies",
  [anon_sym_http_DOTrequest_DOTheaders] = "http.request.headers",
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = "http.request.headers.names",
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = "http.request.headers.values",
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = "http.request.accepted_languages",
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = "ip.geoip.is_in_european_union",
  [anon_sym_ssl] = "ssl",
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = "cf.bot_management.verified_bot",
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = "cf.bot_management.js_detection.passed",
  [anon_sym_cf_DOTclient_DOTbot] = "cf.client.bot",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = "cf.tls_client_auth.cert_revoked",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = "cf.tls_client_auth.cert_verified",
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = "http.request.headers.truncated",
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
  [sym_group] = "group",
  [sym_boolean] = "boolean",
  [sym__ip] = "_ip",
  [sym_ip_range] = "ip_range",
  [sym_not_operator] = "not_operator",
  [sym__number_array] = "_number_array",
  [sym__bool_array] = "_bool_array",
  [sym__string_array] = "_string_array",
  [sym__string_array_expansion] = "_string_array_expansion",
  [sym__boollike_field] = "_boollike_field",
  [sym__numberlike_field] = "_numberlike_field",
  [sym__stringlike_field] = "_stringlike_field",
  [sym_number_field] = "number_field",
  [sym_ip_field] = "ip_field",
  [sym_string_field] = "string_field",
  [sym_bytes_field] = "bytes_field",
  [sym_map_string_array_field] = "map_string_array_field",
  [sym_array_string_field] = "array_string_field",
  [sym_bool_field] = "bool_field",
  [aux_sym_source_file_repeat1] = "source_file_repeat1",
  [aux_sym_ip_set_repeat1] = "ip_set_repeat1",
  [aux_sym_string_set_repeat1] = "string_set_repeat1",
  [aux_sym_number_set_repeat1] = "number_set_repeat1",
  [aux_sym_string_func_repeat1] = "string_func_repeat1",
  [aux_sym_string_func_repeat2] = "string_func_repeat2",
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
  [anon_sym_lookup_json_string] = anon_sym_lookup_json_string,
  [anon_sym_lower] = anon_sym_lower,
  [anon_sym_regex_replace] = anon_sym_regex_replace,
  [anon_sym_remove_bytes] = anon_sym_remove_bytes,
  [anon_sym_to_string] = anon_sym_to_string,
  [anon_sym_upper] = anon_sym_upper,
  [anon_sym_url_decode] = anon_sym_url_decode,
  [anon_sym_uuidv4] = anon_sym_uuidv4,
  [anon_sym_len] = anon_sym_len,
  [anon_sym_ends_with] = anon_sym_ends_with,
  [anon_sym_starts_with] = anon_sym_starts_with,
  [anon_sym_any] = anon_sym_any,
  [anon_sym_all] = anon_sym_all,
  [anon_sym_LBRACK_STAR_RBRACK] = anon_sym_LBRACK_STAR_RBRACK,
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
  [anon_sym_LBRACK] = anon_sym_LBRACK,
  [anon_sym_RBRACK] = anon_sym_RBRACK,
  [anon_sym_STAR] = anon_sym_STAR,
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
  [anon_sym_http_DOTrequest_DOTcookies] = anon_sym_http_DOTrequest_DOTcookies,
  [anon_sym_http_DOTrequest_DOTheaders] = anon_sym_http_DOTrequest_DOTheaders,
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = anon_sym_http_DOTrequest_DOTheaders_DOTnames,
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = anon_sym_http_DOTrequest_DOTaccepted_languages,
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = anon_sym_ip_DOTgeoip_DOTis_in_european_union,
  [anon_sym_ssl] = anon_sym_ssl,
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = anon_sym_cf_DOTbot_management_DOTverified_bot,
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
  [anon_sym_cf_DOTclient_DOTbot] = anon_sym_cf_DOTclient_DOTbot,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
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
  [sym_group] = sym_group,
  [sym_boolean] = sym_boolean,
  [sym__ip] = sym__ip,
  [sym_ip_range] = sym_ip_range,
  [sym_not_operator] = sym_not_operator,
  [sym__number_array] = sym__number_array,
  [sym__bool_array] = sym__bool_array,
  [sym__string_array] = sym__string_array,
  [sym__string_array_expansion] = sym__string_array_expansion,
  [sym__boollike_field] = sym__boollike_field,
  [sym__numberlike_field] = sym__numberlike_field,
  [sym__stringlike_field] = sym__stringlike_field,
  [sym_number_field] = sym_number_field,
  [sym_ip_field] = sym_ip_field,
  [sym_string_field] = sym_string_field,
  [sym_bytes_field] = sym_bytes_field,
  [sym_map_string_array_field] = sym_map_string_array_field,
  [sym_array_string_field] = sym_array_string_field,
  [sym_bool_field] = sym_bool_field,
  [aux_sym_source_file_repeat1] = aux_sym_source_file_repeat1,
  [aux_sym_ip_set_repeat1] = aux_sym_ip_set_repeat1,
  [aux_sym_string_set_repeat1] = aux_sym_string_set_repeat1,
  [aux_sym_number_set_repeat1] = aux_sym_number_set_repeat1,
  [aux_sym_string_func_repeat1] = aux_sym_string_func_repeat1,
  [aux_sym_string_func_repeat2] = aux_sym_string_func_repeat2,
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
  [anon_sym_len] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ends_with] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_starts_with] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_any] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_all] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LBRACK_STAR_RBRACK] = {
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
  [anon_sym_LBRACK] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RBRACK] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_STAR] = {
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
  [anon_sym_http_DOTrequest_DOTcookies] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = {
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
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = {
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
  [sym__number_array] = {
    .visible = false,
    .named = true,
  },
  [sym__bool_array] = {
    .visible = false,
    .named = true,
  },
  [sym__string_array] = {
    .visible = false,
    .named = true,
  },
  [sym__string_array_expansion] = {
    .visible = false,
    .named = true,
  },
  [sym__boollike_field] = {
    .visible = false,
    .named = true,
  },
  [sym__numberlike_field] = {
    .visible = false,
    .named = true,
  },
  [sym__stringlike_field] = {
    .visible = false,
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
  [sym_map_string_array_field] = {
    .visible = true,
    .named = true,
  },
  [sym_array_string_field] = {
    .visible = true,
    .named = true,
  },
  [sym_bool_field] = {
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
  [aux_sym_string_func_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_string_func_repeat2] = {
    .visible = false,
    .named = false,
  },
};

enum {
  field_field = 1,
  field_func = 2,
  field_index = 3,
  field_inner = 4,
  field_ip = 5,
  field_key = 6,
  field_keys = 7,
  field_lhs = 8,
  field_mask = 9,
  field_operator = 10,
  field_regex = 11,
  field_replacement = 12,
  field_rhs = 13,
  field_seed = 14,
  field_source = 15,
  field_value = 16,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_field] = "field",
  [field_func] = "func",
  [field_index] = "index",
  [field_inner] = "inner",
  [field_ip] = "ip",
  [field_key] = "key",
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
  [1] = {.index = 0, .length = 10},
  [2] = {.index = 10, .length = 10},
  [3] = {.index = 20, .length = 20},
  [4] = {.index = 40, .length = 11},
  [5] = {.index = 51, .length = 23},
  [6] = {.index = 74, .length = 13},
  [7] = {.index = 87, .length = 3},
  [8] = {.index = 90, .length = 12},
  [9] = {.index = 102, .length = 2},
  [10] = {.index = 104, .length = 12},
  [11] = {.index = 116, .length = 11},
  [12] = {.index = 127, .length = 1},
  [13] = {.index = 128, .length = 13},
  [14] = {.index = 141, .length = 13},
  [15] = {.index = 154, .length = 2},
  [16] = {.index = 156, .length = 11},
  [17] = {.index = 167, .length = 21},
  [18] = {.index = 188, .length = 13},
  [19] = {.index = 201, .length = 3},
  [20] = {.index = 204, .length = 13},
  [21] = {.index = 217, .length = 14},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_field, 0, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_key, 0, .inherited = true},
    {field_keys, 0, .inherited = true},
    {field_regex, 0, .inherited = true},
    {field_replacement, 0, .inherited = true},
    {field_seed, 0, .inherited = true},
    {field_source, 0, .inherited = true},
    {field_value, 0, .inherited = true},
  [10] =
    {field_field, 1, .inherited = true},
    {field_func, 1, .inherited = true},
    {field_index, 1, .inherited = true},
    {field_key, 1, .inherited = true},
    {field_keys, 1, .inherited = true},
    {field_regex, 1, .inherited = true},
    {field_replacement, 1, .inherited = true},
    {field_seed, 1, .inherited = true},
    {field_source, 1, .inherited = true},
    {field_value, 1, .inherited = true},
  [20] =
    {field_field, 0, .inherited = true},
    {field_field, 1, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_func, 1, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_index, 1, .inherited = true},
    {field_key, 0, .inherited = true},
    {field_key, 1, .inherited = true},
    {field_keys, 0, .inherited = true},
    {field_keys, 1, .inherited = true},
    {field_regex, 0, .inherited = true},
    {field_regex, 1, .inherited = true},
    {field_replacement, 0, .inherited = true},
    {field_replacement, 1, .inherited = true},
    {field_seed, 0, .inherited = true},
    {field_seed, 1, .inherited = true},
    {field_source, 0, .inherited = true},
    {field_source, 1, .inherited = true},
    {field_value, 0, .inherited = true},
    {field_value, 1, .inherited = true},
  [40] =
    {field_field, 1, .inherited = true},
    {field_func, 1, .inherited = true},
    {field_index, 1, .inherited = true},
    {field_inner, 1},
    {field_key, 1, .inherited = true},
    {field_keys, 1, .inherited = true},
    {field_regex, 1, .inherited = true},
    {field_replacement, 1, .inherited = true},
    {field_seed, 1, .inherited = true},
    {field_source, 1, .inherited = true},
    {field_value, 1, .inherited = true},
  [51] =
    {field_field, 0, .inherited = true},
    {field_field, 2, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_func, 2, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 0, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 0, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_lhs, 0},
    {field_operator, 1},
    {field_regex, 0, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_replacement, 0, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_rhs, 2},
    {field_seed, 0, .inherited = true},
    {field_seed, 2, .inherited = true},
    {field_source, 0, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_value, 0, .inherited = true},
    {field_value, 2, .inherited = true},
  [74] =
    {field_field, 0, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_key, 0, .inherited = true},
    {field_keys, 0, .inherited = true},
    {field_lhs, 0},
    {field_operator, 1},
    {field_regex, 0, .inherited = true},
    {field_replacement, 0, .inherited = true},
    {field_rhs, 2},
    {field_seed, 0, .inherited = true},
    {field_source, 0, .inherited = true},
    {field_value, 0, .inherited = true},
  [87] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [90] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_seed, 2, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_value, 2, .inherited = true},
  [102] =
    {field_field, 2},
    {field_func, 0},
  [104] =
    {field_field, 2, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_seed, 2},
    {field_seed, 2, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_value, 2, .inherited = true},
  [116] =
    {field_field, 0, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_index, 2},
    {field_key, 0, .inherited = true},
    {field_keys, 0, .inherited = true},
    {field_regex, 0, .inherited = true},
    {field_replacement, 0, .inherited = true},
    {field_seed, 0, .inherited = true},
    {field_source, 0, .inherited = true},
    {field_value, 0, .inherited = true},
  [127] =
    {field_key, 2},
  [128] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_keys, 3},
    {field_regex, 2, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_seed, 2, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_value, 2, .inherited = true},
  [141] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_field, 3},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_seed, 2, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_value, 2, .inherited = true},
  [154] =
    {field_ip, 0},
    {field_mask, 2},
  [156] =
    {field_field, 4, .inherited = true},
    {field_func, 0},
    {field_func, 4, .inherited = true},
    {field_index, 4, .inherited = true},
    {field_key, 4, .inherited = true},
    {field_keys, 4, .inherited = true},
    {field_regex, 4, .inherited = true},
    {field_replacement, 4, .inherited = true},
    {field_seed, 4, .inherited = true},
    {field_source, 4, .inherited = true},
    {field_value, 4, .inherited = true},
  [167] =
    {field_field, 2, .inherited = true},
    {field_field, 4, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_func, 4, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_index, 4, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_key, 4, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_keys, 4, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_regex, 4, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_replacement, 4, .inherited = true},
    {field_seed, 2, .inherited = true},
    {field_seed, 4, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_source, 4, .inherited = true},
    {field_value, 2, .inherited = true},
    {field_value, 4, .inherited = true},
  [188] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_replacement, 4},
    {field_seed, 2, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_value, 2, .inherited = true},
  [201] =
    {field_field, 2},
    {field_func, 0},
    {field_replacement, 4},
  [204] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_replacement, 2, .inherited = true},
    {field_seed, 2, .inherited = true},
    {field_source, 2, .inherited = true},
    {field_value, 2, .inherited = true},
    {field_value, 4},
  [217] =
    {field_field, 2, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 2, .inherited = true},
    {field_regex, 2, .inherited = true},
    {field_regex, 4},
    {field_replacement, 2, .inherited = true},
    {field_replacement, 6},
    {field_seed, 2, .inherited = true},
    {field_source, 2},
    {field_source, 2, .inherited = true},
    {field_value, 2, .inherited = true},
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
  [72] = 70,
  [73] = 73,
  [74] = 74,
  [75] = 75,
  [76] = 76,
  [77] = 74,
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
  [91] = 88,
  [92] = 92,
  [93] = 93,
  [94] = 92,
  [95] = 93,
  [96] = 96,
  [97] = 90,
  [98] = 98,
  [99] = 96,
  [100] = 100,
  [101] = 98,
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
  [122] = 122,
  [123] = 123,
  [124] = 124,
  [125] = 125,
  [126] = 125,
  [127] = 127,
  [128] = 128,
  [129] = 129,
  [130] = 128,
  [131] = 131,
  [132] = 132,
  [133] = 133,
  [134] = 134,
  [135] = 135,
  [136] = 136,
  [137] = 137,
  [138] = 138,
  [139] = 139,
  [140] = 140,
  [141] = 141,
  [142] = 142,
  [143] = 136,
  [144] = 144,
  [145] = 145,
  [146] = 146,
  [147] = 147,
  [148] = 148,
  [149] = 149,
  [150] = 150,
  [151] = 151,
  [152] = 152,
  [153] = 153,
  [154] = 154,
  [155] = 155,
  [156] = 156,
  [157] = 157,
  [158] = 158,
  [159] = 159,
  [160] = 160,
  [161] = 161,
  [162] = 162,
  [163] = 163,
  [164] = 164,
  [165] = 165,
  [166] = 166,
  [167] = 167,
  [168] = 168,
  [169] = 169,
  [170] = 170,
  [171] = 171,
  [172] = 172,
  [173] = 173,
  [174] = 174,
  [175] = 175,
  [176] = 176,
  [177] = 177,
  [178] = 178,
  [179] = 179,
  [180] = 180,
  [181] = 181,
  [182] = 182,
  [183] = 183,
  [184] = 184,
  [185] = 158,
  [186] = 186,
  [187] = 187,
  [188] = 188,
  [189] = 189,
  [190] = 190,
  [191] = 191,
  [192] = 192,
  [193] = 193,
  [194] = 194,
  [195] = 195,
  [196] = 196,
  [197] = 197,
  [198] = 198,
  [199] = 166,
  [200] = 200,
  [201] = 164,
  [202] = 202,
  [203] = 203,
  [204] = 204,
  [205] = 205,
  [206] = 206,
  [207] = 207,
  [208] = 208,
  [209] = 209,
  [210] = 210,
  [211] = 211,
  [212] = 212,
  [213] = 163,
  [214] = 214,
  [215] = 215,
  [216] = 216,
  [217] = 217,
  [218] = 218,
  [219] = 219,
  [220] = 220,
  [221] = 221,
  [222] = 222,
  [223] = 223,
  [224] = 162,
  [225] = 225,
  [226] = 226,
  [227] = 227,
  [228] = 228,
  [229] = 229,
  [230] = 230,
  [231] = 231,
  [232] = 147,
  [233] = 146,
  [234] = 234,
  [235] = 235,
  [236] = 236,
  [237] = 237,
  [238] = 238,
  [239] = 239,
  [240] = 240,
  [241] = 241,
  [242] = 242,
  [243] = 243,
  [244] = 244,
  [245] = 245,
  [246] = 246,
  [247] = 149,
  [248] = 248,
  [249] = 249,
  [250] = 250,
  [251] = 251,
  [252] = 150,
  [253] = 253,
  [254] = 254,
  [255] = 151,
  [256] = 256,
  [257] = 257,
  [258] = 258,
  [259] = 259,
  [260] = 154,
  [261] = 261,
  [262] = 262,
  [263] = 263,
  [264] = 264,
  [265] = 265,
  [266] = 266,
  [267] = 267,
  [268] = 268,
  [269] = 269,
  [270] = 270,
  [271] = 271,
  [272] = 272,
  [273] = 273,
  [274] = 200,
  [275] = 179,
  [276] = 177,
  [277] = 169,
  [278] = 278,
  [279] = 160,
  [280] = 280,
  [281] = 194,
  [282] = 195,
  [283] = 215,
  [284] = 216,
  [285] = 285,
  [286] = 229,
  [287] = 234,
  [288] = 258,
  [289] = 217,
  [290] = 208,
  [291] = 291,
  [292] = 292,
  [293] = 293,
  [294] = 294,
  [295] = 189,
  [296] = 204,
  [297] = 250,
  [298] = 218,
  [299] = 209,
  [300] = 206,
  [301] = 193,
  [302] = 174,
  [303] = 303,
  [304] = 304,
  [305] = 227,
  [306] = 219,
  [307] = 210,
  [308] = 187,
  [309] = 197,
  [310] = 310,
  [311] = 211,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(704);
      if (lookahead == '!') ADVANCE(770);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == '$') ADVANCE(765);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(732);
      if (lookahead == ')') ADVANCE(734);
      if (lookahead == '*') ADVANCE(774);
      if (lookahead == ',') ADVANCE(733);
      if (lookahead == '/') ADVANCE(759);
      if (lookahead == '3') ADVANCE(749);
      if (lookahead == '<') ADVANCE(724);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '>') ADVANCE(726);
      if (lookahead == '[') ADVANCE(772);
      if (lookahead == ']') ADVANCE(773);
      if (lookahead == '^') ADVANCE(54);
      if (lookahead == 'a') ADVANCE(371);
      if (lookahead == 'c') ADVANCE(294);
      if (lookahead == 'e') ADVANCE(403);
      if (lookahead == 'f') ADVANCE(97);
      if (lookahead == 'g') ADVANCE(200);
      if (lookahead == 'h') ADVANCE(619);
      if (lookahead == 'i') ADVANCE(404);
      if (lookahead == 'l') ADVANCE(201);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(203);
      if (lookahead == 'o') ADVANCE(518);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == 's') ADVANCE(577);
      if (lookahead == 't') ADVANCE(447);
      if (lookahead == 'u') ADVANCE(494);
      if (lookahead == 'x') ADVANCE(451);
      if (lookahead == '{') ADVANCE(712);
      if (lookahead == '|') ADVANCE(702);
      if (lookahead == '}') ADVANCE(713);
      if (lookahead == '~') ADVANCE(730);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(750);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(750);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(51);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == ')') ADVANCE(734);
      if (lookahead == ',') ADVANCE(733);
      if (lookahead == '<') ADVANCE(724);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '>') ADVANCE(726);
      if (lookahead == 'c') ADVANCE(297);
      if (lookahead == 'e') ADVANCE(515);
      if (lookahead == 'g') ADVANCE(200);
      if (lookahead == 'h') ADVANCE(660);
      if (lookahead == 'i') ADVANCE(405);
      if (lookahead == 'l') ADVANCE(222);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(202);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == 't') ADVANCE(446);
      if (lookahead == 'u') ADVANCE(494);
      if (lookahead == '}') ADVANCE(713);
      if (lookahead == '~') ADVANCE(730);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(750);
      END_STATE();
    case 2:
      if (lookahead == '"') ADVANCE(751);
      if (lookahead != 0) ADVANCE(2);
      END_STATE();
    case 3:
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == '3') ADVANCE(761);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(762);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(760);
      END_STATE();
    case 4:
      if (lookahead == '&') ADVANCE(706);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(138);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(308);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(149);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(161);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(112);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(126);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(304);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(363);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(396);
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
      if (lookahead == '.') ADVANCE(139);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(143);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(153);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(127);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(326);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(365);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(141);
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
      if (lookahead == '.') ADVANCE(580);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(165);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(509);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(314);
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
      if (lookahead == '.') ADVANCE(666);
      END_STATE();
    case 41:
      if (lookahead == '.') ADVANCE(393);
      END_STATE();
    case 42:
      if (lookahead == '.') ADVANCE(550);
      END_STATE();
    case 43:
      if (lookahead == '.') ADVANCE(602);
      END_STATE();
    case 44:
      if (lookahead == '.') ADVANCE(150);
      END_STATE();
    case 45:
      if (lookahead == '1') ADVANCE(76);
      if (lookahead == '2') ADVANCE(91);
      END_STATE();
    case 46:
      if (lookahead == '2') ADVANCE(755);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(758);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(757);
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
      if (lookahead == '4') ADVANCE(742);
      END_STATE();
    case 51:
      if (lookahead == '=') ADVANCE(723);
      END_STATE();
    case 52:
      if (lookahead == '=') ADVANCE(722);
      END_STATE();
    case 53:
      if (lookahead == ']') ADVANCE(748);
      END_STATE();
    case 54:
      if (lookahead == '^') ADVANCE(709);
      END_STATE();
    case 55:
      if (lookahead == '_') ADVANCE(389);
      END_STATE();
    case 56:
      if (lookahead == '_') ADVANCE(364);
      END_STATE();
    case 57:
      if (lookahead == '_') ADVANCE(137);
      END_STATE();
    case 58:
      if (lookahead == '_') ADVANCE(337);
      END_STATE();
    case 59:
      if (lookahead == '_') ADVANCE(45);
      END_STATE();
    case 60:
      if (lookahead == '_') ADVANCE(558);
      END_STATE();
    case 61:
      if (lookahead == '_') ADVANCE(688);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(298);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(700);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(581);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(186);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(166);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(504);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(325);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(105);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(382);
      END_STATE();
    case 71:
      if (lookahead == '_') ADVANCE(232);
      END_STATE();
    case 72:
      if (lookahead == '_') ADVANCE(592);
      END_STATE();
    case 73:
      if (lookahead == '_') ADVANCE(542);
      END_STATE();
    case 74:
      if (lookahead == '_') ADVANCE(672);
      END_STATE();
    case 75:
      if (lookahead == '_') ADVANCE(670);
      END_STATE();
    case 76:
      if (lookahead == '_') ADVANCE(343);
      END_STATE();
    case 77:
      if (lookahead == '_') ADVANCE(351);
      END_STATE();
    case 78:
      if (lookahead == '_') ADVANCE(674);
      END_STATE();
    case 79:
      if (lookahead == '_') ADVANCE(193);
      END_STATE();
    case 80:
      if (lookahead == '_') ADVANCE(691);
      END_STATE();
    case 81:
      if (lookahead == '_') ADVANCE(299);
      END_STATE();
    case 82:
      if (lookahead == '_') ADVANCE(142);
      END_STATE();
    case 83:
      if (lookahead == '_') ADVANCE(128);
      END_STATE();
    case 84:
      if (lookahead == '_') ADVANCE(167);
      END_STATE();
    case 85:
      if (lookahead == '_') ADVANCE(605);
      END_STATE();
    case 86:
      if (lookahead == '_') ADVANCE(169);
      END_STATE();
    case 87:
      if (lookahead == '_') ADVANCE(171);
      END_STATE();
    case 88:
      if (lookahead == '_') ADVANCE(172);
      END_STATE();
    case 89:
      if (lookahead == '_') ADVANCE(606);
      END_STATE();
    case 90:
      if (lookahead == '_') ADVANCE(401);
      END_STATE();
    case 91:
      if (lookahead == '_') ADVANCE(362);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(687);
      if (lookahead == 'e') ADVANCE(307);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(295);
      if (lookahead == 'o') ADVANCE(525);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(49);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(49);
      if (lookahead == 's') ADVANCE(79);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(812);
      END_STATE();
    case 97:
      if (lookahead == 'a') ADVANCE(376);
      END_STATE();
    case 98:
      if (lookahead == 'a') ADVANCE(418);
      if (lookahead == 'b') ADVANCE(461);
      if (lookahead == 'm') ADVANCE(104);
      if (lookahead == 'o') ADVANCE(503);
      if (lookahead == 'v') ADVANCE(498);
      END_STATE();
    case 99:
      if (lookahead == 'a') ADVANCE(609);
      END_STATE();
    case 100:
      if (lookahead == 'a') ADVANCE(529);
      END_STATE();
    case 101:
      if (lookahead == 'a') ADVANCE(417);
      END_STATE();
    case 102:
      if (lookahead == 'a') ADVANCE(336);
      END_STATE();
    case 103:
      if (lookahead == 'a') ADVANCE(392);
      END_STATE();
    case 104:
      if (lookahead == 'a') ADVANCE(377);
      END_STATE();
    case 105:
      if (lookahead == 'a') ADVANCE(673);
      END_STATE();
    case 106:
      if (lookahead == 'a') ADVANCE(391);
      END_STATE();
    case 107:
      if (lookahead == 'a') ADVANCE(397);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(611);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(387);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(155);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(196);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(589);
      if (lookahead == 'c') ADVANCE(450);
      if (lookahead == 'i') ADVANCE(585);
      if (lookahead == 's') ADVANCE(663);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(197);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(383);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(421);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(651);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(613);
      if (lookahead == 'o') ADVANCE(410);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(584);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(561);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(416);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(601);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(637);
      END_STATE();
    case 123:
      if (lookahead == 'a') ADVANCE(629);
      END_STATE();
    case 124:
      if (lookahead == 'a') ADVANCE(632);
      END_STATE();
    case 125:
      if (lookahead == 'a') ADVANCE(311);
      END_STATE();
    case 126:
      if (lookahead == 'a') ADVANCE(163);
      if (lookahead == 'c') ADVANCE(490);
      if (lookahead == 'f') ADVANCE(667);
      if (lookahead == 'h') ADVANCE(243);
      if (lookahead == 'm') ADVANCE(266);
      if (lookahead == 't') ADVANCE(355);
      if (lookahead == 'u') ADVANCE(533);
      if (lookahead == 'v') ADVANCE(262);
      END_STATE();
    case 127:
      if (lookahead == 'a') ADVANCE(163);
      if (lookahead == 'c') ADVANCE(490);
      if (lookahead == 'f') ADVANCE(667);
      if (lookahead == 'h') ADVANCE(289);
      if (lookahead == 'm') ADVANCE(266);
      if (lookahead == 'u') ADVANCE(533);
      if (lookahead == 'v') ADVANCE(262);
      END_STATE();
    case 128:
      if (lookahead == 'a') ADVANCE(313);
      END_STATE();
    case 129:
      if (lookahead == 'a') ADVANCE(549);
      END_STATE();
    case 130:
      if (lookahead == 'a') ADVANCE(312);
      END_STATE();
    case 131:
      if (lookahead == 'a') ADVANCE(432);
      END_STATE();
    case 132:
      if (lookahead == 'a') ADVANCE(649);
      END_STATE();
    case 133:
      if (lookahead == 'a') ADVANCE(394);
      END_STATE();
    case 134:
      if (lookahead == 'a') ADVANCE(198);
      END_STATE();
    case 135:
      if (lookahead == 'a') ADVANCE(315);
      END_STATE();
    case 136:
      if (lookahead == 'a') ADVANCE(444);
      END_STATE();
    case 137:
      if (lookahead == 'b') ADVANCE(699);
      END_STATE();
    case 138:
      if (lookahead == 'b') ADVANCE(459);
      if (lookahead == 'c') ADVANCE(375);
      if (lookahead == 'e') ADVANCE(176);
      if (lookahead == 'h') ADVANCE(474);
      if (lookahead == 'r') ADVANCE(101);
      if (lookahead == 't') ADVANCE(322);
      if (lookahead == 'w') ADVANCE(93);
      END_STATE();
    case 139:
      if (lookahead == 'b') ADVANCE(459);
      if (lookahead == 'c') ADVANCE(375);
      if (lookahead == 'e') ADVANCE(176);
      if (lookahead == 'h') ADVANCE(474);
      if (lookahead == 't') ADVANCE(322);
      if (lookahead == 'w') ADVANCE(93);
      END_STATE();
    case 140:
      if (lookahead == 'b') ADVANCE(184);
      END_STATE();
    case 141:
      if (lookahead == 'b') ADVANCE(468);
      END_STATE();
    case 142:
      if (lookahead == 'b') ADVANCE(472);
      END_STATE();
    case 143:
      if (lookahead == 'b') ADVANCE(493);
      if (lookahead == 'h') ADVANCE(474);
      if (lookahead == 'w') ADVANCE(460);
      END_STATE();
    case 144:
      if (lookahead == 'c') ADVANCE(321);
      END_STATE();
    case 145:
      if (lookahead == 'c') ADVANCE(785);
      END_STATE();
    case 146:
      if (lookahead == 'c') ADVANCE(763);
      END_STATE();
    case 147:
      if (lookahead == 'c') ADVANCE(775);
      END_STATE();
    case 148:
      if (lookahead == 'c') ADVANCE(776);
      END_STATE();
    case 149:
      if (lookahead == 'c') ADVANCE(462);
      if (lookahead == 'h') ADVANCE(477);
      if (lookahead == 'r') ADVANCE(208);
      if (lookahead == 'u') ADVANCE(600);
      if (lookahead == 'x') ADVANCE(62);
      END_STATE();
    case 150:
      if (lookahead == 'c') ADVANCE(462);
      if (lookahead == 'h') ADVANCE(477);
      if (lookahead == 'r') ADVANCE(292);
      if (lookahead == 'u') ADVANCE(600);
      if (lookahead == 'x') ADVANCE(62);
      END_STATE();
    case 151:
      if (lookahead == 'c') ADVANCE(146);
      END_STATE();
    case 152:
      if (lookahead == 'c') ADVANCE(475);
      END_STATE();
    case 153:
      if (lookahead == 'c') ADVANCE(450);
      if (lookahead == 's') ADVANCE(663);
      END_STATE();
    case 154:
      if (lookahead == 'c') ADVANCE(8);
      END_STATE();
    case 155:
      if (lookahead == 'c') ADVANCE(213);
      END_STATE();
    case 156:
      if (lookahead == 'c') ADVANCE(215);
      END_STATE();
    case 157:
      if (lookahead == 'c') ADVANCE(657);
      END_STATE();
    case 158:
      if (lookahead == 'c') ADVANCE(237);
      END_STATE();
    case 159:
      if (lookahead == 'c') ADVANCE(108);
      END_STATE();
    case 160:
      if (lookahead == 'c') ADVANCE(108);
      if (lookahead == 't') ADVANCE(102);
      END_STATE();
    case 161:
      if (lookahead == 'c') ADVANCE(341);
      if (lookahead == 'l') ADVANCE(117);
      if (lookahead == 'm') ADVANCE(273);
      if (lookahead == 'p') ADVANCE(480);
      END_STATE();
    case 162:
      if (lookahead == 'c') ADVANCE(483);
      END_STATE();
    case 163:
      if (lookahead == 'c') ADVANCE(158);
      END_STATE();
    case 164:
      if (lookahead == 'c') ADVANCE(132);
      END_STATE();
    case 165:
      if (lookahead == 'c') ADVANCE(278);
      END_STATE();
    case 166:
      if (lookahead == 'c') ADVANCE(384);
      END_STATE();
    case 167:
      if (lookahead == 'c') ADVANCE(481);
      END_STATE();
    case 168:
      if (lookahead == 'c') ADVANCE(484);
      END_STATE();
    case 169:
      if (lookahead == 'c') ADVANCE(482);
      END_STATE();
    case 170:
      if (lookahead == 'c') ADVANCE(487);
      END_STATE();
    case 171:
      if (lookahead == 'c') ADVANCE(485);
      END_STATE();
    case 172:
      if (lookahead == 'c') ADVANCE(486);
      END_STATE();
    case 173:
      if (lookahead == 'd') ADVANCE(707);
      END_STATE();
    case 174:
      if (lookahead == 'd') ADVANCE(707);
      if (lookahead == 'y') ADVANCE(746);
      END_STATE();
    case 175:
      if (lookahead == 'd') ADVANCE(578);
      END_STATE();
    case 176:
      if (lookahead == 'd') ADVANCE(310);
      END_STATE();
    case 177:
      if (lookahead == 'd') ADVANCE(814);
      END_STATE();
    case 178:
      if (lookahead == 'd') ADVANCE(791);
      END_STATE();
    case 179:
      if (lookahead == 'd') ADVANCE(828);
      END_STATE();
    case 180:
      if (lookahead == 'd') ADVANCE(826);
      END_STATE();
    case 181:
      if (lookahead == 'd') ADVANCE(827);
      END_STATE();
    case 182:
      if (lookahead == 'd') ADVANCE(824);
      END_STATE();
    case 183:
      if (lookahead == 'd') ADVANCE(682);
      END_STATE();
    case 184:
      if (lookahead == 'd') ADVANCE(335);
      END_STATE();
    case 185:
      if (lookahead == 'd') ADVANCE(453);
      END_STATE();
    case 186:
      if (lookahead == 'd') ADVANCE(223);
      END_STATE();
    case 187:
      if (lookahead == 'd') ADVANCE(209);
      END_STATE();
    case 188:
      if (lookahead == 'd') ADVANCE(70);
      END_STATE();
    case 189:
      if (lookahead == 'd') ADVANCE(82);
      END_STATE();
    case 190:
      if (lookahead == 'd') ADVANCE(234);
      END_STATE();
    case 191:
      if (lookahead == 'd') ADVANCE(216);
      END_STATE();
    case 192:
      if (lookahead == 'd') ADVANCE(217);
      END_STATE();
    case 193:
      if (lookahead == 'd') ADVANCE(281);
      END_STATE();
    case 194:
      if (lookahead == 'd') ADVANCE(220);
      END_STATE();
    case 195:
      if (lookahead == 'd') ADVANCE(221);
      END_STATE();
    case 196:
      if (lookahead == 'd') ADVANCE(122);
      END_STATE();
    case 197:
      if (lookahead == 'd') ADVANCE(263);
      END_STATE();
    case 198:
      if (lookahead == 'd') ADVANCE(271);
      END_STATE();
    case 199:
      if (lookahead == 'd') ADVANCE(81);
      END_STATE();
    case 200:
      if (lookahead == 'e') ADVANCE(721);
      if (lookahead == 't') ADVANCE(720);
      END_STATE();
    case 201:
      if (lookahead == 'e') ADVANCE(719);
      if (lookahead == 'o') ADVANCE(448);
      if (lookahead == 't') ADVANCE(717);
      END_STATE();
    case 202:
      if (lookahead == 'e') ADVANCE(716);
      END_STATE();
    case 203:
      if (lookahead == 'e') ADVANCE(716);
      if (lookahead == 'o') ADVANCE(610);
      END_STATE();
    case 204:
      if (lookahead == 'e') ADVANCE(692);
      END_STATE();
    case 205:
      if (lookahead == 'e') ADVANCE(752);
      END_STATE();
    case 206:
      if (lookahead == 'e') ADVANCE(753);
      END_STATE();
    case 207:
      if (lookahead == 'e') ADVANCE(763);
      END_STATE();
    case 208:
      if (lookahead == 'e') ADVANCE(300);
      END_STATE();
    case 209:
      if (lookahead == 'e') ADVANCE(741);
      END_STATE();
    case 210:
      if (lookahead == 'e') ADVANCE(787);
      END_STATE();
    case 211:
      if (lookahead == 'e') ADVANCE(517);
      END_STATE();
    case 212:
      if (lookahead == 'e') ADVANCE(781);
      END_STATE();
    case 213:
      if (lookahead == 'e') ADVANCE(737);
      END_STATE();
    case 214:
      if (lookahead == 'e') ADVANCE(780);
      END_STATE();
    case 215:
      if (lookahead == 'e') ADVANCE(784);
      END_STATE();
    case 216:
      if (lookahead == 'e') ADVANCE(802);
      END_STATE();
    case 217:
      if (lookahead == 'e') ADVANCE(801);
      END_STATE();
    case 218:
      if (lookahead == 'e') ADVANCE(778);
      END_STATE();
    case 219:
      if (lookahead == 'e') ADVANCE(813);
      END_STATE();
    case 220:
      if (lookahead == 'e') ADVANCE(805);
      END_STATE();
    case 221:
      if (lookahead == 'e') ADVANCE(806);
      END_STATE();
    case 222:
      if (lookahead == 'e') ADVANCE(718);
      if (lookahead == 'o') ADVANCE(448);
      if (lookahead == 't') ADVANCE(717);
      END_STATE();
    case 223:
      if (lookahead == 'e') ADVANCE(152);
      END_STATE();
    case 224:
      if (lookahead == 'e') ADVANCE(520);
      END_STATE();
    case 225:
      if (lookahead == 'e') ADVANCE(457);
      END_STATE();
    case 226:
      if (lookahead == 'e') ADVANCE(499);
      END_STATE();
    case 227:
      if (lookahead == 'e') ADVANCE(567);
      END_STATE();
    case 228:
      if (lookahead == 'e') ADVANCE(685);
      END_STATE();
    case 229:
      if (lookahead == 'e') ADVANCE(521);
      END_STATE();
    case 230:
      if (lookahead == 'e') ADVANCE(43);
      END_STATE();
    case 231:
      if (lookahead == 'e') ADVANCE(177);
      END_STATE();
    case 232:
      if (lookahead == 'e') ADVANCE(671);
      END_STATE();
    case 233:
      if (lookahead == 'e') ADVANCE(422);
      END_STATE();
    case 234:
      if (lookahead == 'e') ADVANCE(199);
      END_STATE();
    case 235:
      if (lookahead == 'e') ADVANCE(424);
      END_STATE();
    case 236:
      if (lookahead == 'e') ADVANCE(57);
      END_STATE();
    case 237:
      if (lookahead == 'e') ADVANCE(510);
      END_STATE();
    case 238:
      if (lookahead == 'e') ADVANCE(534);
      END_STATE();
    case 239:
      if (lookahead == 'e') ADVANCE(569);
      END_STATE();
    case 240:
      if (lookahead == 'e') ADVANCE(157);
      END_STATE();
    case 241:
      if (lookahead == 'e') ADVANCE(535);
      END_STATE();
    case 242:
      if (lookahead == 'e') ADVANCE(41);
      END_STATE();
    case 243:
      if (lookahead == 'e') ADVANCE(113);
      END_STATE();
    case 244:
      if (lookahead == 'e') ADVANCE(563);
      END_STATE();
    case 245:
      if (lookahead == 'e') ADVANCE(188);
      END_STATE();
    case 246:
      if (lookahead == 'e') ADVANCE(566);
      END_STATE();
    case 247:
      if (lookahead == 'e') ADVANCE(147);
      END_STATE();
    case 248:
      if (lookahead == 'e') ADVANCE(106);
      END_STATE();
    case 249:
      if (lookahead == 'e') ADVANCE(179);
      END_STATE();
    case 250:
      if (lookahead == 'e') ADVANCE(148);
      END_STATE();
    case 251:
      if (lookahead == 'e') ADVANCE(180);
      END_STATE();
    case 252:
      if (lookahead == 'e') ADVANCE(626);
      END_STATE();
    case 253:
      if (lookahead == 'e') ADVANCE(527);
      END_STATE();
    case 254:
      if (lookahead == 'e') ADVANCE(181);
      END_STATE();
    case 255:
      if (lookahead == 'e') ADVANCE(571);
      END_STATE();
    case 256:
      if (lookahead == 'e') ADVANCE(182);
      END_STATE();
    case 257:
      if (lookahead == 'e') ADVANCE(523);
      END_STATE();
    case 258:
      if (lookahead == 'e') ADVANCE(522);
      END_STATE();
    case 259:
      if (lookahead == 'e') ADVANCE(573);
      END_STATE();
    case 260:
      if (lookahead == 'e') ADVANCE(574);
      END_STATE();
    case 261:
      if (lookahead == 'e') ADVANCE(575);
      END_STATE();
    case 262:
      if (lookahead == 'e') ADVANCE(541);
      END_STATE();
    case 263:
      if (lookahead == 'e') ADVANCE(548);
      END_STATE();
    case 264:
      if (lookahead == 'e') ADVANCE(634);
      END_STATE();
    case 265:
      if (lookahead == 'e') ADVANCE(407);
      if (lookahead == 'o') ADVANCE(448);
      END_STATE();
    case 266:
      if (lookahead == 'e') ADVANCE(625);
      END_STATE();
    case 267:
      if (lookahead == 'e') ADVANCE(231);
      END_STATE();
    case 268:
      if (lookahead == 'e') ADVANCE(546);
      END_STATE();
    case 269:
      if (lookahead == 'e') ADVANCE(530);
      END_STATE();
    case 270:
      if (lookahead == 'e') ADVANCE(531);
      END_STATE();
    case 271:
      if (lookahead == 'e') ADVANCE(551);
      END_STATE();
    case 272:
      if (lookahead == 'e') ADVANCE(131);
      END_STATE();
    case 273:
      if (lookahead == 'e') ADVANCE(641);
      END_STATE();
    case 274:
      if (lookahead == 'e') ADVANCE(430);
      END_STATE();
    case 275:
      if (lookahead == 'e') ADVANCE(545);
      END_STATE();
    case 276:
      if (lookahead == 'e') ADVANCE(189);
      END_STATE();
    case 277:
      if (lookahead == 'e') ADVANCE(116);
      END_STATE();
    case 278:
      if (lookahead == 'e') ADVANCE(555);
      END_STATE();
    case 279:
      if (lookahead == 'e') ADVANCE(398);
      END_STATE();
    case 280:
      if (lookahead == 'e') ADVANCE(433);
      END_STATE();
    case 281:
      if (lookahead == 'e') ADVANCE(648);
      END_STATE();
    case 282:
      if (lookahead == 'e') ADVANCE(434);
      END_STATE();
    case 283:
      if (lookahead == 'e') ADVANCE(591);
      END_STATE();
    case 284:
      if (lookahead == 'e') ADVANCE(435);
      END_STATE();
    case 285:
      if (lookahead == 'e') ADVANCE(593);
      END_STATE();
    case 286:
      if (lookahead == 'e') ADVANCE(436);
      END_STATE();
    case 287:
      if (lookahead == 'e') ADVANCE(594);
      END_STATE();
    case 288:
      if (lookahead == 'e') ADVANCE(595);
      END_STATE();
    case 289:
      if (lookahead == 'e') ADVANCE(134);
      END_STATE();
    case 290:
      if (lookahead == 'e') ADVANCE(565);
      END_STATE();
    case 291:
      if (lookahead == 'e') ADVANCE(399);
      END_STATE();
    case 292:
      if (lookahead == 'e') ADVANCE(301);
      END_STATE();
    case 293:
      if (lookahead == 'e') ADVANCE(489);
      END_STATE();
    case 294:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(406);
      END_STATE();
    case 295:
      if (lookahead == 'f') ADVANCE(31);
      END_STATE();
    case 296:
      if (lookahead == 'f') ADVANCE(19);
      if (lookahead == 'o') ADVANCE(442);
      END_STATE();
    case 297:
      if (lookahead == 'f') ADVANCE(20);
      if (lookahead == 'o') ADVANCE(406);
      END_STATE();
    case 298:
      if (lookahead == 'f') ADVANCE(464);
      END_STATE();
    case 299:
      if (lookahead == 'f') ADVANCE(471);
      END_STATE();
    case 300:
      if (lookahead == 'f') ADVANCE(244);
      if (lookahead == 'q') ADVANCE(668);
      END_STATE();
    case 301:
      if (lookahead == 'f') ADVANCE(244);
      if (lookahead == 'q') ADVANCE(680);
      END_STATE();
    case 302:
      if (lookahead == 'f') ADVANCE(353);
      END_STATE();
    case 303:
      if (lookahead == 'f') ADVANCE(348);
      END_STATE();
    case 304:
      if (lookahead == 'f') ADVANCE(681);
      if (lookahead == 'u') ADVANCE(539);
      END_STATE();
    case 305:
      if (lookahead == 'g') ADVANCE(739);
      END_STATE();
    case 306:
      if (lookahead == 'g') ADVANCE(735);
      END_STATE();
    case 307:
      if (lookahead == 'g') ADVANCE(204);
      if (lookahead == 'm') ADVANCE(449);
      END_STATE();
    case 308:
      if (lookahead == 'g') ADVANCE(225);
      if (lookahead == 's') ADVANCE(526);
      END_STATE();
    case 309:
      if (lookahead == 'g') ADVANCE(679);
      END_STATE();
    case 310:
      if (lookahead == 'g') ADVANCE(230);
      END_STATE();
    case 311:
      if (lookahead == 'g') ADVANCE(279);
      END_STATE();
    case 312:
      if (lookahead == 'g') ADVANCE(261);
      END_STATE();
    case 313:
      if (lookahead == 'g') ADVANCE(280);
      END_STATE();
    case 314:
      if (lookahead == 'g') ADVANCE(293);
      if (lookahead == 's') ADVANCE(543);
      END_STATE();
    case 315:
      if (lookahead == 'g') ADVANCE(291);
      END_STATE();
    case 316:
      if (lookahead == 'h') ADVANCE(744);
      END_STATE();
    case 317:
      if (lookahead == 'h') ADVANCE(745);
      END_STATE();
    case 318:
      if (lookahead == 'h') ADVANCE(793);
      END_STATE();
    case 319:
      if (lookahead == 'h') ADVANCE(809);
      END_STATE();
    case 320:
      if (lookahead == 'h') ADVANCE(811);
      END_STATE();
    case 321:
      if (lookahead == 'h') ADVANCE(227);
      END_STATE();
    case 322:
      if (lookahead == 'h') ADVANCE(537);
      if (lookahead == 'l') ADVANCE(582);
      END_STATE();
    case 323:
      if (lookahead == 'h') ADVANCE(463);
      END_STATE();
    case 324:
      if (lookahead == 'h') ADVANCE(32);
      END_STATE();
    case 325:
      if (lookahead == 'h') ADVANCE(118);
      END_STATE();
    case 326:
      if (lookahead == 'h') ADVANCE(655);
      END_STATE();
    case 327:
      if (lookahead == 'i') ADVANCE(701);
      END_STATE();
    case 328:
      if (lookahead == 'i') ADVANCE(792);
      END_STATE();
    case 329:
      if (lookahead == 'i') ADVANCE(782);
      END_STATE();
    case 330:
      if (lookahead == 'i') ADVANCE(808);
      END_STATE();
    case 331:
      if (lookahead == 'i') ADVANCE(790);
      END_STATE();
    case 332:
      if (lookahead == 'i') ADVANCE(807);
      END_STATE();
    case 333:
      if (lookahead == 'i') ADVANCE(183);
      END_STATE();
    case 334:
      if (lookahead == 'i') ADVANCE(302);
      END_STATE();
    case 335:
      if (lookahead == 'i') ADVANCE(684);
      END_STATE();
    case 336:
      if (lookahead == 'i') ADVANCE(420);
      END_STATE();
    case 337:
      if (lookahead == 'i') ADVANCE(495);
      if (lookahead == 'p') ADVANCE(473);
      END_STATE();
    case 338:
      if (lookahead == 'i') ADVANCE(235);
      END_STATE();
    case 339:
      if (lookahead == 'i') ADVANCE(621);
      END_STATE();
    case 340:
      if (lookahead == 'i') ADVANCE(413);
      END_STATE();
    case 341:
      if (lookahead == 'i') ADVANCE(622);
      END_STATE();
    case 342:
      if (lookahead == 'i') ADVANCE(414);
      END_STATE();
    case 343:
      if (lookahead == 'i') ADVANCE(607);
      END_STATE();
    case 344:
      if (lookahead == 'i') ADVANCE(623);
      END_STATE();
    case 345:
      if (lookahead == 'i') ADVANCE(210);
      END_STATE();
    case 346:
      if (lookahead == 'i') ADVANCE(246);
      END_STATE();
    case 347:
      if (lookahead == 'i') ADVANCE(255);
      END_STATE();
    case 348:
      if (lookahead == 'i') ADVANCE(254);
      END_STATE();
    case 349:
      if (lookahead == 'i') ADVANCE(500);
      END_STATE();
    case 350:
      if (lookahead == 'i') ADVANCE(441);
      END_STATE();
    case 351:
      if (lookahead == 'i') ADVANCE(426);
      END_STATE();
    case 352:
      if (lookahead == 'i') ADVANCE(274);
      END_STATE();
    case 353:
      if (lookahead == 'i') ADVANCE(276);
      END_STATE();
    case 354:
      if (lookahead == 'i') ADVANCE(467);
      END_STATE();
    case 355:
      if (lookahead == 'i') ADVANCE(400);
      END_STATE();
    case 356:
      if (lookahead == 'i') ADVANCE(479);
      END_STATE();
    case 357:
      if (lookahead == 'i') ADVANCE(506);
      END_STATE();
    case 358:
      if (lookahead == 'i') ADVANCE(469);
      END_STATE();
    case 359:
      if (lookahead == 'i') ADVANCE(470);
      END_STATE();
    case 360:
      if (lookahead == 'i') ADVANCE(303);
      END_STATE();
    case 361:
      if (lookahead == 'i') ADVANCE(604);
      END_STATE();
    case 362:
      if (lookahead == 'i') ADVANCE(608);
      END_STATE();
    case 363:
      if (lookahead == 'j') ADVANCE(95);
      if (lookahead == 's') ADVANCE(170);
      if (lookahead == 'v') ADVANCE(268);
      END_STATE();
    case 364:
      if (lookahead == 'j') ADVANCE(598);
      END_STATE();
    case 365:
      if (lookahead == 'j') ADVANCE(94);
      END_STATE();
    case 366:
      if (lookahead == 'k') ADVANCE(664);
      END_STATE();
    case 367:
      if (lookahead == 'k') ADVANCE(251);
      END_STATE();
    case 368:
      if (lookahead == 'k') ADVANCE(345);
      END_STATE();
    case 369:
      if (lookahead == 'k') ADVANCE(238);
      END_STATE();
    case 370:
      if (lookahead == 'k') ADVANCE(347);
      END_STATE();
    case 371:
      if (lookahead == 'l') ADVANCE(372);
      if (lookahead == 'n') ADVANCE(174);
      END_STATE();
    case 372:
      if (lookahead == 'l') ADVANCE(747);
      END_STATE();
    case 373:
      if (lookahead == 'l') ADVANCE(822);
      END_STATE();
    case 374:
      if (lookahead == 'l') ADVANCE(65);
      END_STATE();
    case 375:
      if (lookahead == 'l') ADVANCE(338);
      END_STATE();
    case 376:
      if (lookahead == 'l') ADVANCE(579);
      END_STATE();
    case 377:
      if (lookahead == 'l') ADVANCE(689);
      END_STATE();
    case 378:
      if (lookahead == 'l') ADVANCE(110);
      END_STATE();
    case 379:
      if (lookahead == 'l') ADVANCE(329);
      END_STATE();
    case 380:
      if (lookahead == 'l') ADVANCE(74);
      END_STATE();
    case 381:
      if (lookahead == 'l') ADVANCE(380);
      END_STATE();
    case 382:
      if (lookahead == 'l') ADVANCE(120);
      END_STATE();
    case 383:
      if (lookahead == 'l') ADVANCE(675);
      END_STATE();
    case 384:
      if (lookahead == 'l') ADVANCE(352);
      END_STATE();
    case 385:
      if (lookahead == 'l') ADVANCE(78);
      END_STATE();
    case 386:
      if (lookahead == 'l') ADVANCE(385);
      END_STATE();
    case 387:
      if (lookahead == 'l') ADVANCE(86);
      END_STATE();
    case 388:
      if (lookahead == 'm') ADVANCE(777);
      END_STATE();
    case 389:
      if (lookahead == 'm') ADVANCE(115);
      END_STATE();
    case 390:
      if (lookahead == 'm') ADVANCE(327);
      END_STATE();
    case 391:
      if (lookahead == 'm') ADVANCE(63);
      END_STATE();
    case 392:
      if (lookahead == 'm') ADVANCE(242);
      END_STATE();
    case 393:
      if (lookahead == 'm') ADVANCE(264);
      END_STATE();
    case 394:
      if (lookahead == 'm') ADVANCE(259);
      END_STATE();
    case 395:
      if (lookahead == 'm') ADVANCE(72);
      END_STATE();
    case 396:
      if (lookahead == 'm') ADVANCE(596);
      if (lookahead == 's') ADVANCE(247);
      END_STATE();
    case 397:
      if (lookahead == 'm') ADVANCE(505);
      END_STATE();
    case 398:
      if (lookahead == 'm') ADVANCE(282);
      END_STATE();
    case 399:
      if (lookahead == 'm') ADVANCE(286);
      END_STATE();
    case 400:
      if (lookahead == 'm') ADVANCE(287);
      END_STATE();
    case 401:
      if (lookahead == 'm') ADVANCE(136);
      END_STATE();
    case 402:
      if (lookahead == 'n') ADVANCE(175);
      END_STATE();
    case 403:
      if (lookahead == 'n') ADVANCE(175);
      if (lookahead == 'q') ADVANCE(715);
      END_STATE();
    case 404:
      if (lookahead == 'n') ADVANCE(705);
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 405:
      if (lookahead == 'n') ADVANCE(705);
      if (lookahead == 'p') ADVANCE(34);
      END_STATE();
    case 406:
      if (lookahead == 'n') ADVANCE(160);
      END_STATE();
    case 407:
      if (lookahead == 'n') ADVANCE(743);
      END_STATE();
    case 408:
      if (lookahead == 'n') ADVANCE(763);
      END_STATE();
    case 409:
      if (lookahead == 'n') ADVANCE(698);
      END_STATE();
    case 410:
      if (lookahead == 'n') ADVANCE(799);
      END_STATE();
    case 411:
      if (lookahead == 'n') ADVANCE(796);
      END_STATE();
    case 412:
      if (lookahead == 'n') ADVANCE(821);
      END_STATE();
    case 413:
      if (lookahead == 'n') ADVANCE(305);
      END_STATE();
    case 414:
      if (lookahead == 'n') ADVANCE(306);
      END_STATE();
    case 415:
      if (lookahead == 'n') ADVANCE(665);
      END_STATE();
    case 416:
      if (lookahead == 'n') ADVANCE(309);
      END_STATE();
    case 417:
      if (lookahead == 'n') ADVANCE(185);
      END_STATE();
    case 418:
      if (lookahead == 'n') ADVANCE(458);
      END_STATE();
    case 419:
      if (lookahead == 'n') ADVANCE(103);
      END_STATE();
    case 420:
      if (lookahead == 'n') ADVANCE(568);
      END_STATE();
    case 421:
      if (lookahead == 'n') ADVANCE(125);
      END_STATE();
    case 422:
      if (lookahead == 'n') ADVANCE(67);
      END_STATE();
    case 423:
      if (lookahead == 'n') ADVANCE(164);
      END_STATE();
    case 424:
      if (lookahead == 'n') ADVANCE(631);
      END_STATE();
    case 425:
      if (lookahead == 'n') ADVANCE(252);
      END_STATE();
    case 426:
      if (lookahead == 'n') ADVANCE(71);
      END_STATE();
    case 427:
      if (lookahead == 'n') ADVANCE(33);
      END_STATE();
    case 428:
      if (lookahead == 'n') ADVANCE(173);
      END_STATE();
    case 429:
      if (lookahead == 'n') ADVANCE(59);
      END_STATE();
    case 430:
      if (lookahead == 'n') ADVANCE(639);
      END_STATE();
    case 431:
      if (lookahead == 'n') ADVANCE(653);
      if (lookahead == 'u') ADVANCE(440);
      END_STATE();
    case 432:
      if (lookahead == 'n') ADVANCE(75);
      END_STATE();
    case 433:
      if (lookahead == 'n') ADVANCE(615);
      END_STATE();
    case 434:
      if (lookahead == 'n') ADVANCE(638);
      END_STATE();
    case 435:
      if (lookahead == 'n') ADVANCE(616);
      END_STATE();
    case 436:
      if (lookahead == 'n') ADVANCE(646);
      END_STATE();
    case 437:
      if (lookahead == 'n') ADVANCE(219);
      END_STATE();
    case 438:
      if (lookahead == 'n') ADVANCE(133);
      if (lookahead == 't') ADVANCE(532);
      if (lookahead == 'v') ADVANCE(114);
      END_STATE();
    case 439:
      if (lookahead == 'n') ADVANCE(133);
      if (lookahead == 'v') ADVANCE(114);
      END_STATE();
    case 440:
      if (lookahead == 'n') ADVANCE(642);
      END_STATE();
    case 441:
      if (lookahead == 'n') ADVANCE(284);
      END_STATE();
    case 442:
      if (lookahead == 'n') ADVANCE(159);
      END_STATE();
    case 443:
      if (lookahead == 'n') ADVANCE(358);
      END_STATE();
    case 444:
      if (lookahead == 'n') ADVANCE(135);
      END_STATE();
    case 445:
      if (lookahead == 'n') ADVANCE(89);
      END_STATE();
    case 446:
      if (lookahead == 'o') ADVANCE(64);
      END_STATE();
    case 447:
      if (lookahead == 'o') ADVANCE(64);
      if (lookahead == 'r') ADVANCE(662);
      END_STATE();
    case 448:
      if (lookahead == 'o') ADVANCE(366);
      if (lookahead == 'w') ADVANCE(224);
      END_STATE();
    case 449:
      if (lookahead == 'o') ADVANCE(683);
      END_STATE();
    case 450:
      if (lookahead == 'o') ADVANCE(431);
      END_STATE();
    case 451:
      if (lookahead == 'o') ADVANCE(519);
      END_STATE();
    case 452:
      if (lookahead == 'o') ADVANCE(693);
      END_STATE();
    case 453:
      if (lookahead == 'o') ADVANCE(395);
      END_STATE();
    case 454:
      if (lookahead == 'o') ADVANCE(368);
      END_STATE();
    case 455:
      if (lookahead == 'o') ADVANCE(610);
      END_STATE();
    case 456:
      if (lookahead == 'o') ADVANCE(367);
      END_STATE();
    case 457:
      if (lookahead == 'o') ADVANCE(349);
      END_STATE();
    case 458:
      if (lookahead == 'o') ADVANCE(409);
      END_STATE();
    case 459:
      if (lookahead == 'o') ADVANCE(624);
      END_STATE();
    case 460:
      if (lookahead == 'o') ADVANCE(525);
      END_STATE();
    case 461:
      if (lookahead == 'o') ADVANCE(628);
      END_STATE();
    case 462:
      if (lookahead == 'o') ADVANCE(454);
      END_STATE();
    case 463:
      if (lookahead == 'o') ADVANCE(178);
      END_STATE();
    case 464:
      if (lookahead == 'o') ADVANCE(564);
      END_STATE();
    case 465:
      if (lookahead == 'o') ADVANCE(84);
      END_STATE();
    case 466:
      if (lookahead == 'o') ADVANCE(445);
      END_STATE();
    case 467:
      if (lookahead == 'o') ADVANCE(411);
      END_STATE();
    case 468:
      if (lookahead == 'o') ADVANCE(614);
      END_STATE();
    case 469:
      if (lookahead == 'o') ADVANCE(412);
      END_STATE();
    case 470:
      if (lookahead == 'o') ADVANCE(427);
      END_STATE();
    case 471:
      if (lookahead == 'o') ADVANCE(524);
      END_STATE();
    case 472:
      if (lookahead == 'o') ADVANCE(618);
      END_STATE();
    case 473:
      if (lookahead == 'o') ADVANCE(554);
      END_STATE();
    case 474:
      if (lookahead == 'o') ADVANCE(583);
      END_STATE();
    case 475:
      if (lookahead == 'o') ADVANCE(187);
      END_STATE();
    case 476:
      if (lookahead == 'o') ADVANCE(507);
      END_STATE();
    case 477:
      if (lookahead == 'o') ADVANCE(588);
      END_STATE();
    case 478:
      if (lookahead == 'o') ADVANCE(437);
      END_STATE();
    case 479:
      if (lookahead == 'o') ADVANCE(429);
      END_STATE();
    case 480:
      if (lookahead == 'o') ADVANCE(590);
      END_STATE();
    case 481:
      if (lookahead == 'o') ADVANCE(191);
      END_STATE();
    case 482:
      if (lookahead == 'o') ADVANCE(192);
      END_STATE();
    case 483:
      if (lookahead == 'o') ADVANCE(552);
      END_STATE();
    case 484:
      if (lookahead == 'o') ADVANCE(553);
      END_STATE();
    case 485:
      if (lookahead == 'o') ADVANCE(194);
      END_STATE();
    case 486:
      if (lookahead == 'o') ADVANCE(195);
      END_STATE();
    case 487:
      if (lookahead == 'o') ADVANCE(557);
      END_STATE();
    case 488:
      if (lookahead == 'o') ADVANCE(370);
      END_STATE();
    case 489:
      if (lookahead == 'o') ADVANCE(357);
      END_STATE();
    case 490:
      if (lookahead == 'o') ADVANCE(488);
      END_STATE();
    case 491:
      if (lookahead == 'o') ADVANCE(87);
      END_STATE();
    case 492:
      if (lookahead == 'o') ADVANCE(88);
      END_STATE();
    case 493:
      if (lookahead == 'o') ADVANCE(661);
      END_STATE();
    case 494:
      if (lookahead == 'p') ADVANCE(508);
      if (lookahead == 'r') ADVANCE(374);
      if (lookahead == 'u') ADVANCE(333);
      END_STATE();
    case 495:
      if (lookahead == 'p') ADVANCE(786);
      END_STATE();
    case 496:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 497:
      if (lookahead == 'p') ADVANCE(7);
      END_STATE();
    case 498:
      if (lookahead == 'p') ADVANCE(408);
      END_STATE();
    case 499:
      if (lookahead == 'p') ADVANCE(378);
      END_STATE();
    case 500:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 501:
      if (lookahead == 'p') ADVANCE(42);
      END_STATE();
    case 502:
      if (lookahead == 'p') ADVANCE(56);
      END_STATE();
    case 503:
      if (lookahead == 'p') ADVANCE(233);
      END_STATE();
    case 504:
      if (lookahead == 'p') ADVANCE(536);
      END_STATE();
    case 505:
      if (lookahead == 'p') ADVANCE(13);
      END_STATE();
    case 506:
      if (lookahead == 'p') ADVANCE(21);
      END_STATE();
    case 507:
      if (lookahead == 'p') ADVANCE(272);
      END_STATE();
    case 508:
      if (lookahead == 'p') ADVANCE(229);
      END_STATE();
    case 509:
      if (lookahead == 'p') ADVANCE(121);
      END_STATE();
    case 510:
      if (lookahead == 'p') ADVANCE(647);
      END_STATE();
    case 511:
      if (lookahead == 'p') ADVANCE(123);
      if (lookahead == 'q') ADVANCE(676);
      END_STATE();
    case 512:
      if (lookahead == 'p') ADVANCE(124);
      if (lookahead == 'q') ADVANCE(677);
      END_STATE();
    case 513:
      if (lookahead == 'p') ADVANCE(599);
      END_STATE();
    case 514:
      if (lookahead == 'p') ADVANCE(44);
      END_STATE();
    case 515:
      if (lookahead == 'q') ADVANCE(715);
      END_STATE();
    case 516:
      if (lookahead == 'q') ADVANCE(379);
      END_STATE();
    case 517:
      if (lookahead == 'q') ADVANCE(678);
      END_STATE();
    case 518:
      if (lookahead == 'r') ADVANCE(710);
      END_STATE();
    case 519:
      if (lookahead == 'r') ADVANCE(708);
      END_STATE();
    case 520:
      if (lookahead == 'r') ADVANCE(736);
      END_STATE();
    case 521:
      if (lookahead == 'r') ADVANCE(740);
      END_STATE();
    case 522:
      if (lookahead == 'r') ADVANCE(763);
      END_STATE();
    case 523:
      if (lookahead == 'r') ADVANCE(789);
      END_STATE();
    case 524:
      if (lookahead == 'r') ADVANCE(797);
      END_STATE();
    case 525:
      if (lookahead == 'r') ADVANCE(369);
      END_STATE();
    case 526:
      if (lookahead == 'r') ADVANCE(145);
      END_STATE();
    case 527:
      if (lookahead == 'r') ADVANCE(686);
      END_STATE();
    case 528:
      if (lookahead == 'r') ADVANCE(695);
      END_STATE();
    case 529:
      if (lookahead == 'r') ADVANCE(658);
      END_STATE();
    case 530:
      if (lookahead == 'r') ADVANCE(696);
      END_STATE();
    case 531:
      if (lookahead == 'r') ADVANCE(697);
      END_STATE();
    case 532:
      if (lookahead == 'r') ADVANCE(669);
      END_STATE();
    case 533:
      if (lookahead == 'r') ADVANCE(328);
      END_STATE();
    case 534:
      if (lookahead == 'r') ADVANCE(40);
      END_STATE();
    case 535:
      if (lookahead == 'r') ADVANCE(83);
      END_STATE();
    case 536:
      if (lookahead == 'r') ADVANCE(452);
      END_STATE();
    case 537:
      if (lookahead == 'r') ADVANCE(277);
      END_STATE();
    case 538:
      if (lookahead == 'r') ADVANCE(465);
      END_STATE();
    case 539:
      if (lookahead == 'r') ADVANCE(330);
      END_STATE();
    case 540:
      if (lookahead == 'r') ADVANCE(331);
      END_STATE();
    case 541:
      if (lookahead == 'r') ADVANCE(586);
      END_STATE();
    case 542:
      if (lookahead == 'r') ADVANCE(226);
      END_STATE();
    case 543:
      if (lookahead == 'r') ADVANCE(154);
      END_STATE();
    case 544:
      if (lookahead == 'r') ADVANCE(476);
      END_STATE();
    case 545:
      if (lookahead == 'r') ADVANCE(58);
      END_STATE();
    case 546:
      if (lookahead == 'r') ADVANCE(334);
      END_STATE();
    case 547:
      if (lookahead == 'r') ADVANCE(332);
      END_STATE();
    case 548:
      if (lookahead == 'r') ADVANCE(572);
      END_STATE();
    case 549:
      if (lookahead == 'r') ADVANCE(207);
      END_STATE();
    case 550:
      if (lookahead == 'r') ADVANCE(211);
      END_STATE();
    case 551:
      if (lookahead == 'r') ADVANCE(576);
      END_STATE();
    case 552:
      if (lookahead == 'r') ADVANCE(212);
      END_STATE();
    case 553:
      if (lookahead == 'r') ADVANCE(214);
      END_STATE();
    case 554:
      if (lookahead == 'r') ADVANCE(617);
      END_STATE();
    case 555:
      if (lookahead == 'r') ADVANCE(643);
      END_STATE();
    case 556:
      if (lookahead == 'r') ADVANCE(248);
      END_STATE();
    case 557:
      if (lookahead == 'r') ADVANCE(218);
      END_STATE();
    case 558:
      if (lookahead == 'r') ADVANCE(228);
      if (lookahead == 'v') ADVANCE(290);
      END_STATE();
    case 559:
      if (lookahead == 'r') ADVANCE(340);
      END_STATE();
    case 560:
      if (lookahead == 'r') ADVANCE(156);
      if (lookahead == 's') ADVANCE(516);
      if (lookahead == 'x') ADVANCE(587);
      END_STATE();
    case 561:
      if (lookahead == 'r') ADVANCE(190);
      END_STATE();
    case 562:
      if (lookahead == 'r') ADVANCE(342);
      END_STATE();
    case 563:
      if (lookahead == 'r') ADVANCE(257);
      END_STATE();
    case 564:
      if (lookahead == 'r') ADVANCE(690);
      END_STATE();
    case 565:
      if (lookahead == 'r') ADVANCE(360);
      END_STATE();
    case 566:
      if (lookahead == 's') ADVANCE(763);
      END_STATE();
    case 567:
      if (lookahead == 's') ADVANCE(729);
      END_STATE();
    case 568:
      if (lookahead == 's') ADVANCE(728);
      END_STATE();
    case 569:
      if (lookahead == 's') ADVANCE(738);
      END_STATE();
    case 570:
      if (lookahead == 's') ADVANCE(783);
      END_STATE();
    case 571:
      if (lookahead == 's') ADVANCE(815);
      END_STATE();
    case 572:
      if (lookahead == 's') ADVANCE(816);
      END_STATE();
    case 573:
      if (lookahead == 's') ADVANCE(818);
      END_STATE();
    case 574:
      if (lookahead == 's') ADVANCE(819);
      END_STATE();
    case 575:
      if (lookahead == 's') ADVANCE(820);
      END_STATE();
    case 576:
      if (lookahead == 's') ADVANCE(817);
      END_STATE();
    case 577:
      if (lookahead == 's') ADVANCE(373);
      if (lookahead == 't') ADVANCE(100);
      END_STATE();
    case 578:
      if (lookahead == 's') ADVANCE(61);
      END_STATE();
    case 579:
      if (lookahead == 's') ADVANCE(206);
      END_STATE();
    case 580:
      if (lookahead == 's') ADVANCE(162);
      END_STATE();
    case 581:
      if (lookahead == 's') ADVANCE(630);
      END_STATE();
    case 582:
      if (lookahead == 's') ADVANCE(66);
      END_STATE();
    case 583:
      if (lookahead == 's') ADVANCE(633);
      END_STATE();
    case 584:
      if (lookahead == 's') ADVANCE(320);
      END_STATE();
    case 585:
      if (lookahead == 's') ADVANCE(77);
      END_STATE();
    case 586:
      if (lookahead == 's') ADVANCE(354);
      END_STATE();
    case 587:
      if (lookahead == 's') ADVANCE(570);
      END_STATE();
    case 588:
      if (lookahead == 's') ADVANCE(612);
      END_STATE();
    case 589:
      if (lookahead == 's') ADVANCE(415);
      END_STATE();
    case 590:
      if (lookahead == 's') ADVANCE(650);
      END_STATE();
    case 591:
      if (lookahead == 's') ADVANCE(635);
      END_STATE();
    case 592:
      if (lookahead == 's') ADVANCE(267);
      END_STATE();
    case 593:
      if (lookahead == 's') ADVANCE(636);
      END_STATE();
    case 594:
      if (lookahead == 's') ADVANCE(640);
      END_STATE();
    case 595:
      if (lookahead == 's') ADVANCE(645);
      END_STATE();
    case 596:
      if (lookahead == 's') ADVANCE(250);
      END_STATE();
    case 597:
      if (lookahead == 's') ADVANCE(256);
      END_STATE();
    case 598:
      if (lookahead == 's') ADVANCE(466);
      END_STATE();
    case 599:
      if (lookahead == 's') ADVANCE(654);
      END_STATE();
    case 600:
      if (lookahead == 's') ADVANCE(241);
      END_STATE();
    case 601:
      if (lookahead == 's') ADVANCE(597);
      END_STATE();
    case 602:
      if (lookahead == 's') ADVANCE(253);
      END_STATE();
    case 603:
      if (lookahead == 's') ADVANCE(80);
      END_STATE();
    case 604:
      if (lookahead == 's') ADVANCE(356);
      END_STATE();
    case 605:
      if (lookahead == 's') ADVANCE(168);
      END_STATE();
    case 606:
      if (lookahead == 's') ADVANCE(656);
      END_STATE();
    case 607:
      if (lookahead == 's') ADVANCE(491);
      END_STATE();
    case 608:
      if (lookahead == 's') ADVANCE(492);
      END_STATE();
    case 609:
      if (lookahead == 't') ADVANCE(144);
      END_STATE();
    case 610:
      if (lookahead == 't') ADVANCE(768);
      END_STATE();
    case 611:
      if (lookahead == 't') ADVANCE(731);
      END_STATE();
    case 612:
      if (lookahead == 't') ADVANCE(788);
      END_STATE();
    case 613:
      if (lookahead == 't') ADVANCE(798);
      END_STATE();
    case 614:
      if (lookahead == 't') ADVANCE(825);
      END_STATE();
    case 615:
      if (lookahead == 't') ADVANCE(795);
      END_STATE();
    case 616:
      if (lookahead == 't') ADVANCE(803);
      END_STATE();
    case 617:
      if (lookahead == 't') ADVANCE(779);
      END_STATE();
    case 618:
      if (lookahead == 't') ADVANCE(823);
      END_STATE();
    case 619:
      if (lookahead == 't') ADVANCE(620);
      END_STATE();
    case 620:
      if (lookahead == 't') ADVANCE(497);
      END_STATE();
    case 621:
      if (lookahead == 't') ADVANCE(316);
      END_STATE();
    case 622:
      if (lookahead == 't') ADVANCE(694);
      END_STATE();
    case 623:
      if (lookahead == 't') ADVANCE(317);
      END_STATE();
    case 624:
      if (lookahead == 't') ADVANCE(55);
      END_STATE();
    case 625:
      if (lookahead == 't') ADVANCE(323);
      END_STATE();
    case 626:
      if (lookahead == 't') ADVANCE(151);
      END_STATE();
    case 627:
      if (lookahead == 't') ADVANCE(324);
      END_STATE();
    case 628:
      if (lookahead == 't') ADVANCE(425);
      END_STATE();
    case 629:
      if (lookahead == 't') ADVANCE(318);
      END_STATE();
    case 630:
      if (lookahead == 't') ADVANCE(559);
      END_STATE();
    case 631:
      if (lookahead == 't') ADVANCE(25);
      END_STATE();
    case 632:
      if (lookahead == 't') ADVANCE(319);
      END_STATE();
    case 633:
      if (lookahead == 't') ADVANCE(419);
      END_STATE();
    case 634:
      if (lookahead == 't') ADVANCE(111);
      END_STATE();
    case 635:
      if (lookahead == 't') ADVANCE(10);
      END_STATE();
    case 636:
      if (lookahead == 't') ADVANCE(11);
      END_STATE();
    case 637:
      if (lookahead == 't') ADVANCE(96);
      END_STATE();
    case 638:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 639:
      if (lookahead == 't') ADVANCE(69);
      END_STATE();
    case 640:
      if (lookahead == 't') ADVANCE(107);
      END_STATE();
    case 641:
      if (lookahead == 't') ADVANCE(538);
      END_STATE();
    case 642:
      if (lookahead == 't') ADVANCE(528);
      END_STATE();
    case 643:
      if (lookahead == 't') ADVANCE(60);
      END_STATE();
    case 644:
      if (lookahead == 't') ADVANCE(239);
      END_STATE();
    case 645:
      if (lookahead == 't') ADVANCE(22);
      END_STATE();
    case 646:
      if (lookahead == 't') ADVANCE(24);
      END_STATE();
    case 647:
      if (lookahead == 't') ADVANCE(245);
      END_STATE();
    case 648:
      if (lookahead == 't') ADVANCE(240);
      END_STATE();
    case 649:
      if (lookahead == 't') ADVANCE(249);
      END_STATE();
    case 650:
      if (lookahead == 't') ADVANCE(109);
      END_STATE();
    case 651:
      if (lookahead == 't') ADVANCE(85);
      END_STATE();
    case 652:
      if (lookahead == 't') ADVANCE(501);
      END_STATE();
    case 653:
      if (lookahead == 't') ADVANCE(350);
      END_STATE();
    case 654:
      if (lookahead == 't') ADVANCE(556);
      END_STATE();
    case 655:
      if (lookahead == 't') ADVANCE(652);
      END_STATE();
    case 656:
      if (lookahead == 't') ADVANCE(562);
      END_STATE();
    case 657:
      if (lookahead == 't') ADVANCE(359);
      END_STATE();
    case 658:
      if (lookahead == 't') ADVANCE(603);
      END_STATE();
    case 659:
      if (lookahead == 't') ADVANCE(514);
      END_STATE();
    case 660:
      if (lookahead == 't') ADVANCE(659);
      END_STATE();
    case 661:
      if (lookahead == 't') ADVANCE(90);
      END_STATE();
    case 662:
      if (lookahead == 'u') ADVANCE(205);
      END_STATE();
    case 663:
      if (lookahead == 'u') ADVANCE(140);
      END_STATE();
    case 664:
      if (lookahead == 'u') ADVANCE(502);
      END_STATE();
    case 665:
      if (lookahead == 'u') ADVANCE(388);
      END_STATE();
    case 666:
      if (lookahead == 'u') ADVANCE(513);
      END_STATE();
    case 667:
      if (lookahead == 'u') ADVANCE(381);
      END_STATE();
    case 668:
      if (lookahead == 'u') ADVANCE(283);
      END_STATE();
    case 669:
      if (lookahead == 'u') ADVANCE(423);
      END_STATE();
    case 670:
      if (lookahead == 'u') ADVANCE(443);
      END_STATE();
    case 671:
      if (lookahead == 'u') ADVANCE(544);
      END_STATE();
    case 672:
      if (lookahead == 'u') ADVANCE(540);
      END_STATE();
    case 673:
      if (lookahead == 'u') ADVANCE(627);
      END_STATE();
    case 674:
      if (lookahead == 'u') ADVANCE(547);
      END_STATE();
    case 675:
      if (lookahead == 'u') ADVANCE(260);
      END_STATE();
    case 676:
      if (lookahead == 'u') ADVANCE(269);
      END_STATE();
    case 677:
      if (lookahead == 'u') ADVANCE(270);
      END_STATE();
    case 678:
      if (lookahead == 'u') ADVANCE(285);
      END_STATE();
    case 679:
      if (lookahead == 'u') ADVANCE(130);
      END_STATE();
    case 680:
      if (lookahead == 'u') ADVANCE(288);
      END_STATE();
    case 681:
      if (lookahead == 'u') ADVANCE(386);
      END_STATE();
    case 682:
      if (lookahead == 'v') ADVANCE(50);
      END_STATE();
    case 683:
      if (lookahead == 'v') ADVANCE(236);
      END_STATE();
    case 684:
      if (lookahead == 'v') ADVANCE(361);
      END_STATE();
    case 685:
      if (lookahead == 'v') ADVANCE(456);
      END_STATE();
    case 686:
      if (lookahead == 'v') ADVANCE(275);
      END_STATE();
    case 687:
      if (lookahead == 'w') ADVANCE(23);
      END_STATE();
    case 688:
      if (lookahead == 'w') ADVANCE(339);
      END_STATE();
    case 689:
      if (lookahead == 'w') ADVANCE(129);
      END_STATE();
    case 690:
      if (lookahead == 'w') ADVANCE(119);
      END_STATE();
    case 691:
      if (lookahead == 'w') ADVANCE(344);
      END_STATE();
    case 692:
      if (lookahead == 'x') ADVANCE(73);
      END_STATE();
    case 693:
      if (lookahead == 'x') ADVANCE(346);
      END_STATE();
    case 694:
      if (lookahead == 'y') ADVANCE(800);
      END_STATE();
    case 695:
      if (lookahead == 'y') ADVANCE(804);
      END_STATE();
    case 696:
      if (lookahead == 'y') ADVANCE(794);
      END_STATE();
    case 697:
      if (lookahead == 'y') ADVANCE(810);
      END_STATE();
    case 698:
      if (lookahead == 'y') ADVANCE(390);
      END_STATE();
    case 699:
      if (lookahead == 'y') ADVANCE(644);
      END_STATE();
    case 700:
      if (lookahead == 'z') ADVANCE(478);
      END_STATE();
    case 701:
      if (lookahead == 'z') ADVANCE(258);
      END_STATE();
    case 702:
      if (lookahead == '|') ADVANCE(711);
      END_STATE();
    case 703:
      if (eof) ADVANCE(704);
      if (lookahead == '!') ADVANCE(769);
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(732);
      if (lookahead == ')') ADVANCE(734);
      if (lookahead == '/') ADVANCE(759);
      if (lookahead == '2') ADVANCE(15);
      if (lookahead == '[') ADVANCE(771);
      if (lookahead == '^') ADVANCE(54);
      if (lookahead == 'a') ADVANCE(428);
      if (lookahead == 'c') ADVANCE(296);
      if (lookahead == 'e') ADVANCE(402);
      if (lookahead == 'f') ADVANCE(97);
      if (lookahead == 'h') ADVANCE(619);
      if (lookahead == 'i') ADVANCE(496);
      if (lookahead == 'l') ADVANCE(265);
      if (lookahead == 'n') ADVANCE(455);
      if (lookahead == 'o') ADVANCE(518);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == 's') ADVANCE(577);
      if (lookahead == 't') ADVANCE(447);
      if (lookahead == 'u') ADVANCE(494);
      if (lookahead == 'x') ADVANCE(451);
      if (lookahead == '|') ADVANCE(702);
      if (lookahead == '}') ADVANCE(713);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(17);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(703)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(18);
      END_STATE();
    case 704:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 705:
      ACCEPT_TOKEN(anon_sym_in);
      END_STATE();
    case 706:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 707:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 708:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 709:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 710:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 711:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 712:
      ACCEPT_TOKEN(anon_sym_LBRACE);
      END_STATE();
    case 713:
      ACCEPT_TOKEN(anon_sym_RBRACE);
      END_STATE();
    case 714:
      ACCEPT_TOKEN(sym_comment);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(714);
      END_STATE();
    case 715:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 716:
      ACCEPT_TOKEN(anon_sym_ne);
      END_STATE();
    case 717:
      ACCEPT_TOKEN(anon_sym_lt);
      END_STATE();
    case 718:
      ACCEPT_TOKEN(anon_sym_le);
      END_STATE();
    case 719:
      ACCEPT_TOKEN(anon_sym_le);
      if (lookahead == 'n') ADVANCE(743);
      END_STATE();
    case 720:
      ACCEPT_TOKEN(anon_sym_gt);
      END_STATE();
    case 721:
      ACCEPT_TOKEN(anon_sym_ge);
      END_STATE();
    case 722:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 723:
      ACCEPT_TOKEN(anon_sym_BANG_EQ);
      END_STATE();
    case 724:
      ACCEPT_TOKEN(anon_sym_LT);
      if (lookahead == '=') ADVANCE(725);
      END_STATE();
    case 725:
      ACCEPT_TOKEN(anon_sym_LT_EQ);
      END_STATE();
    case 726:
      ACCEPT_TOKEN(anon_sym_GT);
      if (lookahead == '=') ADVANCE(727);
      END_STATE();
    case 727:
      ACCEPT_TOKEN(anon_sym_GT_EQ);
      END_STATE();
    case 728:
      ACCEPT_TOKEN(anon_sym_contains);
      END_STATE();
    case 729:
      ACCEPT_TOKEN(anon_sym_matches);
      END_STATE();
    case 730:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 731:
      ACCEPT_TOKEN(anon_sym_concat);
      END_STATE();
    case 732:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 733:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 734:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 735:
      ACCEPT_TOKEN(anon_sym_lookup_json_string);
      END_STATE();
    case 736:
      ACCEPT_TOKEN(anon_sym_lower);
      END_STATE();
    case 737:
      ACCEPT_TOKEN(anon_sym_regex_replace);
      END_STATE();
    case 738:
      ACCEPT_TOKEN(anon_sym_remove_bytes);
      END_STATE();
    case 739:
      ACCEPT_TOKEN(anon_sym_to_string);
      END_STATE();
    case 740:
      ACCEPT_TOKEN(anon_sym_upper);
      END_STATE();
    case 741:
      ACCEPT_TOKEN(anon_sym_url_decode);
      END_STATE();
    case 742:
      ACCEPT_TOKEN(anon_sym_uuidv4);
      END_STATE();
    case 743:
      ACCEPT_TOKEN(anon_sym_len);
      END_STATE();
    case 744:
      ACCEPT_TOKEN(anon_sym_ends_with);
      END_STATE();
    case 745:
      ACCEPT_TOKEN(anon_sym_starts_with);
      END_STATE();
    case 746:
      ACCEPT_TOKEN(anon_sym_any);
      END_STATE();
    case 747:
      ACCEPT_TOKEN(anon_sym_all);
      END_STATE();
    case 748:
      ACCEPT_TOKEN(anon_sym_LBRACK_STAR_RBRACK);
      END_STATE();
    case 749:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(750);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(750);
      END_STATE();
    case 750:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(750);
      END_STATE();
    case 751:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 752:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 753:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 754:
      ACCEPT_TOKEN(sym_ipv4);
      END_STATE();
    case 755:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '5') ADVANCE(756);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(754);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(757);
      END_STATE();
    case 756:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(754);
      END_STATE();
    case 757:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(754);
      END_STATE();
    case 758:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(757);
      END_STATE();
    case 759:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 760:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      END_STATE();
    case 761:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(760);
      END_STATE();
    case 762:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(760);
      END_STATE();
    case 763:
      ACCEPT_TOKEN(sym_ip_list);
      END_STATE();
    case 764:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == '.') ADVANCE(98);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(767);
      END_STATE();
    case 765:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'c') ADVANCE(766);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(767);
      END_STATE();
    case 766:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'f') ADVANCE(764);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(767);
      END_STATE();
    case 767:
      ACCEPT_TOKEN(sym_ip_list);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(767);
      END_STATE();
    case 768:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 769:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 770:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(723);
      END_STATE();
    case 771:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 772:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      if (lookahead == '*') ADVANCE(53);
      END_STATE();
    case 773:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 774:
      ACCEPT_TOKEN(anon_sym_STAR);
      END_STATE();
    case 775:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 776:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 777:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 778:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 779:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 780:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 781:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(560);
      END_STATE();
    case 782:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 783:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 784:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 785:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(161);
      END_STATE();
    case 786:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 787:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 788:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 789:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 790:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 791:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 792:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(511);
      END_STATE();
    case 793:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 794:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 795:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 796:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 797:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 798:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 799:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 800:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 801:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 802:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 803:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 804:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 805:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 806:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 807:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 808:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(512);
      END_STATE();
    case 809:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 810:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 811:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 812:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 813:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 814:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 815:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 816:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(438);
      END_STATE();
    case 817:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(439);
      END_STATE();
    case 818:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTnames);
      END_STATE();
    case 819:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTvalues);
      END_STATE();
    case 820:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTaccepted_languages);
      END_STATE();
    case 821:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 822:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 823:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 824:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 825:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 826:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 827:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_verified);
      END_STATE();
    case 828:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTtruncated);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 703},
  [2] = {.lex_state = 703},
  [3] = {.lex_state = 703},
  [4] = {.lex_state = 703},
  [5] = {.lex_state = 703},
  [6] = {.lex_state = 703},
  [7] = {.lex_state = 703},
  [8] = {.lex_state = 703},
  [9] = {.lex_state = 703},
  [10] = {.lex_state = 703},
  [11] = {.lex_state = 703},
  [12] = {.lex_state = 703},
  [13] = {.lex_state = 703},
  [14] = {.lex_state = 703},
  [15] = {.lex_state = 703},
  [16] = {.lex_state = 703},
  [17] = {.lex_state = 703},
  [18] = {.lex_state = 703},
  [19] = {.lex_state = 703},
  [20] = {.lex_state = 703},
  [21] = {.lex_state = 703},
  [22] = {.lex_state = 703},
  [23] = {.lex_state = 703},
  [24] = {.lex_state = 703},
  [25] = {.lex_state = 703},
  [26] = {.lex_state = 703},
  [27] = {.lex_state = 703},
  [28] = {.lex_state = 703},
  [29] = {.lex_state = 703},
  [30] = {.lex_state = 703},
  [31] = {.lex_state = 703},
  [32] = {.lex_state = 703},
  [33] = {.lex_state = 703},
  [34] = {.lex_state = 703},
  [35] = {.lex_state = 703},
  [36] = {.lex_state = 703},
  [37] = {.lex_state = 703},
  [38] = {.lex_state = 703},
  [39] = {.lex_state = 703},
  [40] = {.lex_state = 703},
  [41] = {.lex_state = 703},
  [42] = {.lex_state = 703},
  [43] = {.lex_state = 703},
  [44] = {.lex_state = 703},
  [45] = {.lex_state = 703},
  [46] = {.lex_state = 703},
  [47] = {.lex_state = 703},
  [48] = {.lex_state = 703},
  [49] = {.lex_state = 703},
  [50] = {.lex_state = 703},
  [51] = {.lex_state = 703},
  [52] = {.lex_state = 703},
  [53] = {.lex_state = 703},
  [54] = {.lex_state = 703},
  [55] = {.lex_state = 703},
  [56] = {.lex_state = 703},
  [57] = {.lex_state = 703},
  [58] = {.lex_state = 703},
  [59] = {.lex_state = 703},
  [60] = {.lex_state = 703},
  [61] = {.lex_state = 703},
  [62] = {.lex_state = 703},
  [63] = {.lex_state = 703},
  [64] = {.lex_state = 1},
  [65] = {.lex_state = 1},
  [66] = {.lex_state = 0},
  [67] = {.lex_state = 0},
  [68] = {.lex_state = 0},
  [69] = {.lex_state = 0},
  [70] = {.lex_state = 0},
  [71] = {.lex_state = 0},
  [72] = {.lex_state = 0},
  [73] = {.lex_state = 0},
  [74] = {.lex_state = 0},
  [75] = {.lex_state = 0},
  [76] = {.lex_state = 0},
  [77] = {.lex_state = 0},
  [78] = {.lex_state = 0},
  [79] = {.lex_state = 0},
  [80] = {.lex_state = 0},
  [81] = {.lex_state = 0},
  [82] = {.lex_state = 0},
  [83] = {.lex_state = 0},
  [84] = {.lex_state = 0},
  [85] = {.lex_state = 0},
  [86] = {.lex_state = 0},
  [87] = {.lex_state = 703},
  [88] = {.lex_state = 0},
  [89] = {.lex_state = 0},
  [90] = {.lex_state = 0},
  [91] = {.lex_state = 0},
  [92] = {.lex_state = 0},
  [93] = {.lex_state = 0},
  [94] = {.lex_state = 0},
  [95] = {.lex_state = 0},
  [96] = {.lex_state = 0},
  [97] = {.lex_state = 0},
  [98] = {.lex_state = 0},
  [99] = {.lex_state = 0},
  [100] = {.lex_state = 0},
  [101] = {.lex_state = 0},
  [102] = {.lex_state = 1},
  [103] = {.lex_state = 1},
  [104] = {.lex_state = 1},
  [105] = {.lex_state = 1},
  [106] = {.lex_state = 1},
  [107] = {.lex_state = 1},
  [108] = {.lex_state = 1},
  [109] = {.lex_state = 1},
  [110] = {.lex_state = 1},
  [111] = {.lex_state = 1},
  [112] = {.lex_state = 1},
  [113] = {.lex_state = 1},
  [114] = {.lex_state = 1},
  [115] = {.lex_state = 1},
  [116] = {.lex_state = 1},
  [117] = {.lex_state = 1},
  [118] = {.lex_state = 1},
  [119] = {.lex_state = 1},
  [120] = {.lex_state = 1},
  [121] = {.lex_state = 0},
  [122] = {.lex_state = 1},
  [123] = {.lex_state = 703},
  [124] = {.lex_state = 1},
  [125] = {.lex_state = 703},
  [126] = {.lex_state = 703},
  [127] = {.lex_state = 703},
  [128] = {.lex_state = 1},
  [129] = {.lex_state = 703},
  [130] = {.lex_state = 1},
  [131] = {.lex_state = 1},
  [132] = {.lex_state = 1},
  [133] = {.lex_state = 1},
  [134] = {.lex_state = 1},
  [135] = {.lex_state = 1},
  [136] = {.lex_state = 1},
  [137] = {.lex_state = 1},
  [138] = {.lex_state = 1},
  [139] = {.lex_state = 0},
  [140] = {.lex_state = 703},
  [141] = {.lex_state = 0},
  [142] = {.lex_state = 1},
  [143] = {.lex_state = 1},
  [144] = {.lex_state = 0},
  [145] = {.lex_state = 1},
  [146] = {.lex_state = 0},
  [147] = {.lex_state = 0},
  [148] = {.lex_state = 0},
  [149] = {.lex_state = 0},
  [150] = {.lex_state = 0},
  [151] = {.lex_state = 0},
  [152] = {.lex_state = 0},
  [153] = {.lex_state = 0},
  [154] = {.lex_state = 0},
  [155] = {.lex_state = 0},
  [156] = {.lex_state = 0},
  [157] = {.lex_state = 0},
  [158] = {.lex_state = 0},
  [159] = {.lex_state = 0},
  [160] = {.lex_state = 0},
  [161] = {.lex_state = 0},
  [162] = {.lex_state = 0},
  [163] = {.lex_state = 0},
  [164] = {.lex_state = 0},
  [165] = {.lex_state = 1},
  [166] = {.lex_state = 0},
  [167] = {.lex_state = 0},
  [168] = {.lex_state = 0},
  [169] = {.lex_state = 0},
  [170] = {.lex_state = 0},
  [171] = {.lex_state = 0},
  [172] = {.lex_state = 0},
  [173] = {.lex_state = 0},
  [174] = {.lex_state = 0},
  [175] = {.lex_state = 0},
  [176] = {.lex_state = 0},
  [177] = {.lex_state = 0},
  [178] = {.lex_state = 0},
  [179] = {.lex_state = 0},
  [180] = {.lex_state = 0},
  [181] = {.lex_state = 0},
  [182] = {.lex_state = 0},
  [183] = {.lex_state = 0},
  [184] = {.lex_state = 0},
  [185] = {.lex_state = 703},
  [186] = {.lex_state = 0},
  [187] = {.lex_state = 0},
  [188] = {.lex_state = 0},
  [189] = {.lex_state = 0},
  [190] = {.lex_state = 0},
  [191] = {.lex_state = 0},
  [192] = {.lex_state = 0},
  [193] = {.lex_state = 0},
  [194] = {.lex_state = 0},
  [195] = {.lex_state = 0},
  [196] = {.lex_state = 0},
  [197] = {.lex_state = 0},
  [198] = {.lex_state = 0},
  [199] = {.lex_state = 703},
  [200] = {.lex_state = 0},
  [201] = {.lex_state = 703},
  [202] = {.lex_state = 703},
  [203] = {.lex_state = 0},
  [204] = {.lex_state = 0},
  [205] = {.lex_state = 0},
  [206] = {.lex_state = 0},
  [207] = {.lex_state = 0},
  [208] = {.lex_state = 0},
  [209] = {.lex_state = 0},
  [210] = {.lex_state = 0},
  [211] = {.lex_state = 0},
  [212] = {.lex_state = 3},
  [213] = {.lex_state = 703},
  [214] = {.lex_state = 0},
  [215] = {.lex_state = 0},
  [216] = {.lex_state = 0},
  [217] = {.lex_state = 0},
  [218] = {.lex_state = 0},
  [219] = {.lex_state = 0},
  [220] = {.lex_state = 0},
  [221] = {.lex_state = 1},
  [222] = {.lex_state = 0},
  [223] = {.lex_state = 1},
  [224] = {.lex_state = 703},
  [225] = {.lex_state = 1},
  [226] = {.lex_state = 0},
  [227] = {.lex_state = 0},
  [228] = {.lex_state = 0},
  [229] = {.lex_state = 0},
  [230] = {.lex_state = 0},
  [231] = {.lex_state = 0},
  [232] = {.lex_state = 703},
  [233] = {.lex_state = 703},
  [234] = {.lex_state = 0},
  [235] = {.lex_state = 0},
  [236] = {.lex_state = 0},
  [237] = {.lex_state = 0},
  [238] = {.lex_state = 0},
  [239] = {.lex_state = 0},
  [240] = {.lex_state = 0},
  [241] = {.lex_state = 0},
  [242] = {.lex_state = 0},
  [243] = {.lex_state = 0},
  [244] = {.lex_state = 0},
  [245] = {.lex_state = 0},
  [246] = {.lex_state = 0},
  [247] = {.lex_state = 703},
  [248] = {.lex_state = 0},
  [249] = {.lex_state = 0},
  [250] = {.lex_state = 0},
  [251] = {.lex_state = 0},
  [252] = {.lex_state = 703},
  [253] = {.lex_state = 0},
  [254] = {.lex_state = 1},
  [255] = {.lex_state = 703},
  [256] = {.lex_state = 1},
  [257] = {.lex_state = 1},
  [258] = {.lex_state = 0},
  [259] = {.lex_state = 0},
  [260] = {.lex_state = 703},
  [261] = {.lex_state = 1},
  [262] = {.lex_state = 1},
  [263] = {.lex_state = 1},
  [264] = {.lex_state = 1},
  [265] = {.lex_state = 1},
  [266] = {.lex_state = 1},
  [267] = {.lex_state = 1},
  [268] = {.lex_state = 1},
  [269] = {.lex_state = 1},
  [270] = {.lex_state = 703},
  [271] = {.lex_state = 703},
  [272] = {.lex_state = 703},
  [273] = {.lex_state = 703},
  [274] = {.lex_state = 0},
  [275] = {.lex_state = 0},
  [276] = {.lex_state = 0},
  [277] = {.lex_state = 0},
  [278] = {.lex_state = 0},
  [279] = {.lex_state = 703},
  [280] = {.lex_state = 703},
  [281] = {.lex_state = 0},
  [282] = {.lex_state = 0},
  [283] = {.lex_state = 0},
  [284] = {.lex_state = 0},
  [285] = {.lex_state = 0},
  [286] = {.lex_state = 0},
  [287] = {.lex_state = 0},
  [288] = {.lex_state = 0},
  [289] = {.lex_state = 0},
  [290] = {.lex_state = 0},
  [291] = {.lex_state = 0},
  [292] = {.lex_state = 0},
  [293] = {.lex_state = 0},
  [294] = {.lex_state = 0},
  [295] = {.lex_state = 0},
  [296] = {.lex_state = 0},
  [297] = {.lex_state = 0},
  [298] = {.lex_state = 0},
  [299] = {.lex_state = 0},
  [300] = {.lex_state = 0},
  [301] = {.lex_state = 0},
  [302] = {.lex_state = 0},
  [303] = {.lex_state = 0},
  [304] = {.lex_state = 0},
  [305] = {.lex_state = 0},
  [306] = {.lex_state = 0},
  [307] = {.lex_state = 0},
  [308] = {.lex_state = 0},
  [309] = {.lex_state = 0},
  [310] = {.lex_state = 0},
  [311] = {.lex_state = 0},
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
    [anon_sym_lookup_json_string] = ACTIONS(1),
    [anon_sym_lower] = ACTIONS(1),
    [anon_sym_regex_replace] = ACTIONS(1),
    [anon_sym_remove_bytes] = ACTIONS(1),
    [anon_sym_to_string] = ACTIONS(1),
    [anon_sym_upper] = ACTIONS(1),
    [anon_sym_url_decode] = ACTIONS(1),
    [anon_sym_uuidv4] = ACTIONS(1),
    [anon_sym_len] = ACTIONS(1),
    [anon_sym_ends_with] = ACTIONS(1),
    [anon_sym_starts_with] = ACTIONS(1),
    [anon_sym_any] = ACTIONS(1),
    [anon_sym_all] = ACTIONS(1),
    [anon_sym_LBRACK_STAR_RBRACK] = ACTIONS(1),
    [sym_number] = ACTIONS(1),
    [sym_string] = ACTIONS(1),
    [anon_sym_true] = ACTIONS(1),
    [anon_sym_false] = ACTIONS(1),
    [anon_sym_SLASH] = ACTIONS(1),
    [aux_sym_ip_range_token1] = ACTIONS(1),
    [sym_ip_list] = ACTIONS(1),
    [anon_sym_not] = ACTIONS(1),
    [anon_sym_BANG] = ACTIONS(1),
    [anon_sym_LBRACK] = ACTIONS(1),
    [anon_sym_RBRACK] = ACTIONS(1),
    [anon_sym_STAR] = ACTIONS(1),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(1),
    [anon_sym_ssl] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(1),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(1),
  },
  [1] = {
    [sym_source_file] = STATE(278),
    [sym__expression] = STATE(62),
    [sym_not_expression] = STATE(62),
    [sym_in_expression] = STATE(62),
    [sym_compound_expression] = STATE(62),
    [sym_simple_expression] = STATE(62),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(62),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(5),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [2] = {
    [sym__expression] = STATE(62),
    [sym_not_expression] = STATE(62),
    [sym_in_expression] = STATE(62),
    [sym_compound_expression] = STATE(62),
    [sym_simple_expression] = STATE(62),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(62),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(51),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(53),
    [anon_sym_LPAREN] = ACTIONS(56),
    [anon_sym_lookup_json_string] = ACTIONS(59),
    [anon_sym_lower] = ACTIONS(62),
    [anon_sym_regex_replace] = ACTIONS(65),
    [anon_sym_remove_bytes] = ACTIONS(68),
    [anon_sym_to_string] = ACTIONS(71),
    [anon_sym_upper] = ACTIONS(62),
    [anon_sym_url_decode] = ACTIONS(62),
    [anon_sym_uuidv4] = ACTIONS(74),
    [anon_sym_len] = ACTIONS(77),
    [anon_sym_ends_with] = ACTIONS(80),
    [anon_sym_starts_with] = ACTIONS(80),
    [anon_sym_true] = ACTIONS(83),
    [anon_sym_false] = ACTIONS(83),
    [anon_sym_not] = ACTIONS(86),
    [anon_sym_BANG] = ACTIONS(86),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(89),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(89),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(89),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(89),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(89),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(89),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(92),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(89),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(89),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(89),
    [anon_sym_ip_DOTsrc] = ACTIONS(95),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(98),
    [anon_sym_http_DOTcookie] = ACTIONS(101),
    [anon_sym_http_DOThost] = ACTIONS(101),
    [anon_sym_http_DOTreferer] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(101),
    [anon_sym_http_DOTuser_agent] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(101),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(101),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(101),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(101),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(101),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(101),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(101),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(101),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(101),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(101),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(101),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(101),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(104),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(101),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(101),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(101),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(101),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(107),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(110),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(113),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(116),
    [anon_sym_ssl] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(116),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(116),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(116),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(116),
  },
  [3] = {
    [sym__expression] = STATE(62),
    [sym_not_expression] = STATE(62),
    [sym_in_expression] = STATE(62),
    [sym_compound_expression] = STATE(62),
    [sym_simple_expression] = STATE(62),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(62),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(119),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [4] = {
    [sym__expression] = STATE(20),
    [sym_not_expression] = STATE(20),
    [sym_in_expression] = STATE(20),
    [sym_compound_expression] = STATE(20),
    [sym_simple_expression] = STATE(20),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(20),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [5] = {
    [sym__expression] = STATE(121),
    [sym_not_expression] = STATE(121),
    [sym_in_expression] = STATE(121),
    [sym_compound_expression] = STATE(121),
    [sym_simple_expression] = STATE(121),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(121),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [6] = {
    [sym__expression] = STATE(55),
    [sym_not_expression] = STATE(55),
    [sym_in_expression] = STATE(55),
    [sym_compound_expression] = STATE(55),
    [sym_simple_expression] = STATE(55),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(55),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [7] = {
    [sym__expression] = STATE(56),
    [sym_not_expression] = STATE(56),
    [sym_in_expression] = STATE(56),
    [sym_compound_expression] = STATE(56),
    [sym_simple_expression] = STATE(56),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(56),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [8] = {
    [sym__expression] = STATE(57),
    [sym_not_expression] = STATE(57),
    [sym_in_expression] = STATE(57),
    [sym_compound_expression] = STATE(57),
    [sym_simple_expression] = STATE(57),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(57),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [9] = {
    [sym__expression] = STATE(58),
    [sym_not_expression] = STATE(58),
    [sym_in_expression] = STATE(58),
    [sym_compound_expression] = STATE(58),
    [sym_simple_expression] = STATE(58),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(58),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [10] = {
    [sym__expression] = STATE(59),
    [sym_not_expression] = STATE(59),
    [sym_in_expression] = STATE(59),
    [sym_compound_expression] = STATE(59),
    [sym_simple_expression] = STATE(59),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(59),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [11] = {
    [sym__expression] = STATE(60),
    [sym_not_expression] = STATE(60),
    [sym_in_expression] = STATE(60),
    [sym_compound_expression] = STATE(60),
    [sym_simple_expression] = STATE(60),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(118),
    [sym__string_lhs] = STATE(114),
    [sym_string_func] = STATE(114),
    [sym_number_func] = STATE(118),
    [sym_bool_func] = STATE(21),
    [sym_group] = STATE(60),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__number_array] = STATE(273),
    [sym__bool_array] = STATE(272),
    [sym__string_array] = STATE(271),
    [sym__boollike_field] = STATE(27),
    [sym__numberlike_field] = STATE(117),
    [sym__stringlike_field] = STATE(102),
    [sym_number_field] = STATE(117),
    [sym_ip_field] = STATE(124),
    [sym_string_field] = STATE(102),
    [sym_map_string_array_field] = STATE(270),
    [sym_array_string_field] = STATE(271),
    [sym_bool_field] = STATE(27),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [anon_sym_len] = ACTIONS(23),
    [anon_sym_ends_with] = ACTIONS(25),
    [anon_sym_starts_with] = ACTIONS(25),
    [anon_sym_true] = ACTIONS(27),
    [anon_sym_false] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(29),
    [anon_sym_BANG] = ACTIONS(29),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(31),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(31),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(31),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(31),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(31),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(31),
    [anon_sym_ip_DOTsrc] = ACTIONS(35),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(39),
    [anon_sym_http_DOThost] = ACTIONS(39),
    [anon_sym_http_DOTreferer] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_http_DOTuser_agent] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(39),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(39),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(39),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(39),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(39),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(39),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(39),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(39),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(47),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(49),
    [anon_sym_ssl] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(49),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(49),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(49),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(121),
    [anon_sym_AMP_AMP] = ACTIONS(121),
    [anon_sym_and] = ACTIONS(121),
    [anon_sym_xor] = ACTIONS(121),
    [anon_sym_CARET_CARET] = ACTIONS(121),
    [anon_sym_or] = ACTIONS(121),
    [anon_sym_PIPE_PIPE] = ACTIONS(121),
    [anon_sym_RBRACE] = ACTIONS(121),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(121),
    [anon_sym_LPAREN] = ACTIONS(121),
    [anon_sym_RPAREN] = ACTIONS(121),
    [anon_sym_lookup_json_string] = ACTIONS(121),
    [anon_sym_lower] = ACTIONS(121),
    [anon_sym_regex_replace] = ACTIONS(121),
    [anon_sym_remove_bytes] = ACTIONS(121),
    [anon_sym_to_string] = ACTIONS(121),
    [anon_sym_upper] = ACTIONS(121),
    [anon_sym_url_decode] = ACTIONS(121),
    [anon_sym_uuidv4] = ACTIONS(121),
    [anon_sym_len] = ACTIONS(121),
    [anon_sym_ends_with] = ACTIONS(121),
    [anon_sym_starts_with] = ACTIONS(121),
    [anon_sym_true] = ACTIONS(121),
    [anon_sym_false] = ACTIONS(121),
    [sym_ipv4] = ACTIONS(121),
    [anon_sym_SLASH] = ACTIONS(123),
    [anon_sym_not] = ACTIONS(121),
    [anon_sym_BANG] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(121),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(121),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(121),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(121),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(121),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(125),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(121),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(121),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(121),
    [anon_sym_ip_DOTsrc] = ACTIONS(125),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(121),
    [anon_sym_http_DOTcookie] = ACTIONS(121),
    [anon_sym_http_DOThost] = ACTIONS(121),
    [anon_sym_http_DOTreferer] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(125),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(121),
    [anon_sym_http_DOTuser_agent] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(121),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(121),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(121),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(121),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(121),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(121),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(121),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(121),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(121),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(121),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(121),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(121),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(125),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(121),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(121),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(121),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(121),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(125),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(121),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(121),
    [anon_sym_ssl] = ACTIONS(121),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(121),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(121),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(121),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(121),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(121),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(121),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(127),
    [anon_sym_AMP_AMP] = ACTIONS(127),
    [anon_sym_and] = ACTIONS(127),
    [anon_sym_xor] = ACTIONS(127),
    [anon_sym_CARET_CARET] = ACTIONS(127),
    [anon_sym_or] = ACTIONS(127),
    [anon_sym_PIPE_PIPE] = ACTIONS(127),
    [anon_sym_RBRACE] = ACTIONS(127),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(127),
    [anon_sym_LPAREN] = ACTIONS(127),
    [anon_sym_RPAREN] = ACTIONS(127),
    [anon_sym_lookup_json_string] = ACTIONS(127),
    [anon_sym_lower] = ACTIONS(127),
    [anon_sym_regex_replace] = ACTIONS(127),
    [anon_sym_remove_bytes] = ACTIONS(127),
    [anon_sym_to_string] = ACTIONS(127),
    [anon_sym_upper] = ACTIONS(127),
    [anon_sym_url_decode] = ACTIONS(127),
    [anon_sym_uuidv4] = ACTIONS(127),
    [anon_sym_len] = ACTIONS(127),
    [anon_sym_ends_with] = ACTIONS(127),
    [anon_sym_starts_with] = ACTIONS(127),
    [anon_sym_true] = ACTIONS(127),
    [anon_sym_false] = ACTIONS(127),
    [sym_ipv4] = ACTIONS(127),
    [anon_sym_not] = ACTIONS(127),
    [anon_sym_BANG] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(127),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(127),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(127),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(127),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(127),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(129),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(127),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(127),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(127),
    [anon_sym_ip_DOTsrc] = ACTIONS(129),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(127),
    [anon_sym_http_DOTcookie] = ACTIONS(127),
    [anon_sym_http_DOThost] = ACTIONS(127),
    [anon_sym_http_DOTreferer] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(129),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(127),
    [anon_sym_http_DOTuser_agent] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(127),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(127),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(127),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(127),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(127),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(127),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(127),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(127),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(127),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(127),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(127),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(127),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(129),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(127),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(127),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(127),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(127),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(129),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(127),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(127),
    [anon_sym_ssl] = ACTIONS(127),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(127),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(127),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(127),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(127),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(127),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(127),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(135),
    [anon_sym_AMP_AMP] = ACTIONS(135),
    [anon_sym_and] = ACTIONS(135),
    [anon_sym_xor] = ACTIONS(135),
    [anon_sym_CARET_CARET] = ACTIONS(135),
    [anon_sym_or] = ACTIONS(135),
    [anon_sym_PIPE_PIPE] = ACTIONS(135),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(135),
    [anon_sym_LPAREN] = ACTIONS(135),
    [anon_sym_RPAREN] = ACTIONS(135),
    [anon_sym_lookup_json_string] = ACTIONS(135),
    [anon_sym_lower] = ACTIONS(135),
    [anon_sym_regex_replace] = ACTIONS(135),
    [anon_sym_remove_bytes] = ACTIONS(135),
    [anon_sym_to_string] = ACTIONS(135),
    [anon_sym_upper] = ACTIONS(135),
    [anon_sym_url_decode] = ACTIONS(135),
    [anon_sym_uuidv4] = ACTIONS(135),
    [anon_sym_len] = ACTIONS(135),
    [anon_sym_ends_with] = ACTIONS(135),
    [anon_sym_starts_with] = ACTIONS(135),
    [anon_sym_true] = ACTIONS(135),
    [anon_sym_false] = ACTIONS(135),
    [anon_sym_not] = ACTIONS(135),
    [anon_sym_BANG] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(135),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(135),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(135),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(135),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(135),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(137),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(135),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(135),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(135),
    [anon_sym_ip_DOTsrc] = ACTIONS(137),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(135),
    [anon_sym_http_DOTcookie] = ACTIONS(135),
    [anon_sym_http_DOThost] = ACTIONS(135),
    [anon_sym_http_DOTreferer] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(135),
    [anon_sym_http_DOTuser_agent] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(135),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(135),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(135),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(135),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(135),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(135),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(135),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(135),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(135),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(135),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(135),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(135),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(135),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(135),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(135),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(135),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(135),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(135),
    [anon_sym_ssl] = ACTIONS(135),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(135),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(135),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(135),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(135),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(135),
  },
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(139),
    [anon_sym_AMP_AMP] = ACTIONS(139),
    [anon_sym_and] = ACTIONS(139),
    [anon_sym_xor] = ACTIONS(139),
    [anon_sym_CARET_CARET] = ACTIONS(139),
    [anon_sym_or] = ACTIONS(139),
    [anon_sym_PIPE_PIPE] = ACTIONS(139),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(139),
    [anon_sym_LPAREN] = ACTIONS(139),
    [anon_sym_RPAREN] = ACTIONS(139),
    [anon_sym_lookup_json_string] = ACTIONS(139),
    [anon_sym_lower] = ACTIONS(139),
    [anon_sym_regex_replace] = ACTIONS(139),
    [anon_sym_remove_bytes] = ACTIONS(139),
    [anon_sym_to_string] = ACTIONS(139),
    [anon_sym_upper] = ACTIONS(139),
    [anon_sym_url_decode] = ACTIONS(139),
    [anon_sym_uuidv4] = ACTIONS(139),
    [anon_sym_len] = ACTIONS(139),
    [anon_sym_ends_with] = ACTIONS(139),
    [anon_sym_starts_with] = ACTIONS(139),
    [anon_sym_true] = ACTIONS(139),
    [anon_sym_false] = ACTIONS(139),
    [anon_sym_not] = ACTIONS(139),
    [anon_sym_BANG] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(139),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(139),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(139),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(139),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(139),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(139),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(139),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(139),
    [anon_sym_ip_DOTsrc] = ACTIONS(141),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(139),
    [anon_sym_http_DOTcookie] = ACTIONS(139),
    [anon_sym_http_DOThost] = ACTIONS(139),
    [anon_sym_http_DOTreferer] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(139),
    [anon_sym_http_DOTuser_agent] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(139),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(139),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(139),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(139),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(139),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(139),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(139),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(139),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(139),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(139),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(139),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(139),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(139),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(139),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(139),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(139),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(139),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(139),
    [anon_sym_ssl] = ACTIONS(139),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(139),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(139),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(139),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(139),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(139),
  },
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [20] = {
    [ts_builtin_sym_end] = ACTIONS(143),
    [anon_sym_AMP_AMP] = ACTIONS(143),
    [anon_sym_and] = ACTIONS(143),
    [anon_sym_xor] = ACTIONS(143),
    [anon_sym_CARET_CARET] = ACTIONS(143),
    [anon_sym_or] = ACTIONS(143),
    [anon_sym_PIPE_PIPE] = ACTIONS(143),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(143),
    [anon_sym_LPAREN] = ACTIONS(143),
    [anon_sym_RPAREN] = ACTIONS(143),
    [anon_sym_lookup_json_string] = ACTIONS(143),
    [anon_sym_lower] = ACTIONS(143),
    [anon_sym_regex_replace] = ACTIONS(143),
    [anon_sym_remove_bytes] = ACTIONS(143),
    [anon_sym_to_string] = ACTIONS(143),
    [anon_sym_upper] = ACTIONS(143),
    [anon_sym_url_decode] = ACTIONS(143),
    [anon_sym_uuidv4] = ACTIONS(143),
    [anon_sym_len] = ACTIONS(143),
    [anon_sym_ends_with] = ACTIONS(143),
    [anon_sym_starts_with] = ACTIONS(143),
    [anon_sym_true] = ACTIONS(143),
    [anon_sym_false] = ACTIONS(143),
    [anon_sym_not] = ACTIONS(143),
    [anon_sym_BANG] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(143),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(143),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(143),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(143),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(143),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(145),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(143),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(143),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(143),
    [anon_sym_ip_DOTsrc] = ACTIONS(145),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(143),
    [anon_sym_http_DOTcookie] = ACTIONS(143),
    [anon_sym_http_DOThost] = ACTIONS(143),
    [anon_sym_http_DOTreferer] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(143),
    [anon_sym_http_DOTuser_agent] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(143),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(143),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(143),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(143),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(143),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(143),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(143),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(143),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(143),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(143),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(143),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(143),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(145),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(143),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(143),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(143),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(143),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(145),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(143),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(143),
    [anon_sym_ssl] = ACTIONS(143),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(143),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(143),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(143),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(143),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(143),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(143),
  },
  [21] = {
    [ts_builtin_sym_end] = ACTIONS(147),
    [anon_sym_AMP_AMP] = ACTIONS(147),
    [anon_sym_and] = ACTIONS(147),
    [anon_sym_xor] = ACTIONS(147),
    [anon_sym_CARET_CARET] = ACTIONS(147),
    [anon_sym_or] = ACTIONS(147),
    [anon_sym_PIPE_PIPE] = ACTIONS(147),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(147),
    [anon_sym_LPAREN] = ACTIONS(147),
    [anon_sym_RPAREN] = ACTIONS(147),
    [anon_sym_lookup_json_string] = ACTIONS(147),
    [anon_sym_lower] = ACTIONS(147),
    [anon_sym_regex_replace] = ACTIONS(147),
    [anon_sym_remove_bytes] = ACTIONS(147),
    [anon_sym_to_string] = ACTIONS(147),
    [anon_sym_upper] = ACTIONS(147),
    [anon_sym_url_decode] = ACTIONS(147),
    [anon_sym_uuidv4] = ACTIONS(147),
    [anon_sym_len] = ACTIONS(147),
    [anon_sym_ends_with] = ACTIONS(147),
    [anon_sym_starts_with] = ACTIONS(147),
    [anon_sym_true] = ACTIONS(147),
    [anon_sym_false] = ACTIONS(147),
    [anon_sym_not] = ACTIONS(147),
    [anon_sym_BANG] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(147),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(147),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(147),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(147),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(149),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(147),
    [anon_sym_ip_DOTsrc] = ACTIONS(149),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(147),
    [anon_sym_http_DOTcookie] = ACTIONS(147),
    [anon_sym_http_DOThost] = ACTIONS(147),
    [anon_sym_http_DOTreferer] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(147),
    [anon_sym_http_DOTuser_agent] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(147),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(147),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(147),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(147),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(147),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(147),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(147),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(147),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(147),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(147),
    [anon_sym_ssl] = ACTIONS(147),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(147),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(147),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(147),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(147),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(147),
  },
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [23] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [24] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [25] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [26] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(151),
    [anon_sym_AMP_AMP] = ACTIONS(151),
    [anon_sym_and] = ACTIONS(151),
    [anon_sym_xor] = ACTIONS(151),
    [anon_sym_CARET_CARET] = ACTIONS(151),
    [anon_sym_or] = ACTIONS(151),
    [anon_sym_PIPE_PIPE] = ACTIONS(151),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(151),
    [anon_sym_LPAREN] = ACTIONS(151),
    [anon_sym_RPAREN] = ACTIONS(151),
    [anon_sym_lookup_json_string] = ACTIONS(151),
    [anon_sym_lower] = ACTIONS(151),
    [anon_sym_regex_replace] = ACTIONS(151),
    [anon_sym_remove_bytes] = ACTIONS(151),
    [anon_sym_to_string] = ACTIONS(151),
    [anon_sym_upper] = ACTIONS(151),
    [anon_sym_url_decode] = ACTIONS(151),
    [anon_sym_uuidv4] = ACTIONS(151),
    [anon_sym_len] = ACTIONS(151),
    [anon_sym_ends_with] = ACTIONS(151),
    [anon_sym_starts_with] = ACTIONS(151),
    [anon_sym_true] = ACTIONS(151),
    [anon_sym_false] = ACTIONS(151),
    [anon_sym_not] = ACTIONS(151),
    [anon_sym_BANG] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(151),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(151),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(151),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(151),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(151),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(151),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(151),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(151),
    [anon_sym_ip_DOTsrc] = ACTIONS(153),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(151),
    [anon_sym_http_DOTcookie] = ACTIONS(151),
    [anon_sym_http_DOThost] = ACTIONS(151),
    [anon_sym_http_DOTreferer] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(151),
    [anon_sym_http_DOTuser_agent] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(151),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(151),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(151),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(151),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(151),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(151),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(151),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(151),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(151),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(151),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(151),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(151),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(151),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(151),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(151),
    [anon_sym_ssl] = ACTIONS(151),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(151),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(151),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(151),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(151),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(151),
  },
  [28] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [29] = {
    [ts_builtin_sym_end] = ACTIONS(155),
    [anon_sym_AMP_AMP] = ACTIONS(155),
    [anon_sym_and] = ACTIONS(155),
    [anon_sym_xor] = ACTIONS(155),
    [anon_sym_CARET_CARET] = ACTIONS(155),
    [anon_sym_or] = ACTIONS(155),
    [anon_sym_PIPE_PIPE] = ACTIONS(155),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(155),
    [anon_sym_LPAREN] = ACTIONS(155),
    [anon_sym_RPAREN] = ACTIONS(155),
    [anon_sym_lookup_json_string] = ACTIONS(155),
    [anon_sym_lower] = ACTIONS(155),
    [anon_sym_regex_replace] = ACTIONS(155),
    [anon_sym_remove_bytes] = ACTIONS(155),
    [anon_sym_to_string] = ACTIONS(155),
    [anon_sym_upper] = ACTIONS(155),
    [anon_sym_url_decode] = ACTIONS(155),
    [anon_sym_uuidv4] = ACTIONS(155),
    [anon_sym_len] = ACTIONS(155),
    [anon_sym_ends_with] = ACTIONS(155),
    [anon_sym_starts_with] = ACTIONS(155),
    [anon_sym_true] = ACTIONS(155),
    [anon_sym_false] = ACTIONS(155),
    [anon_sym_not] = ACTIONS(155),
    [anon_sym_BANG] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(155),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(155),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(155),
    [anon_sym_ip_DOTsrc] = ACTIONS(157),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(155),
    [anon_sym_http_DOTcookie] = ACTIONS(155),
    [anon_sym_http_DOThost] = ACTIONS(155),
    [anon_sym_http_DOTreferer] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(155),
    [anon_sym_http_DOTuser_agent] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(155),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(155),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(155),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(155),
    [anon_sym_ssl] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(155),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(155),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(155),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(155),
  },
  [30] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [31] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [32] = {
    [ts_builtin_sym_end] = ACTIONS(159),
    [anon_sym_AMP_AMP] = ACTIONS(159),
    [anon_sym_and] = ACTIONS(159),
    [anon_sym_xor] = ACTIONS(159),
    [anon_sym_CARET_CARET] = ACTIONS(159),
    [anon_sym_or] = ACTIONS(159),
    [anon_sym_PIPE_PIPE] = ACTIONS(159),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(159),
    [anon_sym_LPAREN] = ACTIONS(159),
    [anon_sym_RPAREN] = ACTIONS(159),
    [anon_sym_lookup_json_string] = ACTIONS(159),
    [anon_sym_lower] = ACTIONS(159),
    [anon_sym_regex_replace] = ACTIONS(159),
    [anon_sym_remove_bytes] = ACTIONS(159),
    [anon_sym_to_string] = ACTIONS(159),
    [anon_sym_upper] = ACTIONS(159),
    [anon_sym_url_decode] = ACTIONS(159),
    [anon_sym_uuidv4] = ACTIONS(159),
    [anon_sym_len] = ACTIONS(159),
    [anon_sym_ends_with] = ACTIONS(159),
    [anon_sym_starts_with] = ACTIONS(159),
    [anon_sym_true] = ACTIONS(159),
    [anon_sym_false] = ACTIONS(159),
    [anon_sym_not] = ACTIONS(159),
    [anon_sym_BANG] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(159),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(159),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(159),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(159),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(159),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(161),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(159),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(159),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(159),
    [anon_sym_ip_DOTsrc] = ACTIONS(161),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(159),
    [anon_sym_http_DOTcookie] = ACTIONS(159),
    [anon_sym_http_DOThost] = ACTIONS(159),
    [anon_sym_http_DOTreferer] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(159),
    [anon_sym_http_DOTuser_agent] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(159),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(159),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(159),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(159),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(159),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(159),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(159),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(159),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(159),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(159),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(159),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(159),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(159),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(159),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(159),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(159),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(159),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(159),
    [anon_sym_ssl] = ACTIONS(159),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(159),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(159),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(159),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(159),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(159),
  },
  [33] = {
    [ts_builtin_sym_end] = ACTIONS(163),
    [anon_sym_AMP_AMP] = ACTIONS(163),
    [anon_sym_and] = ACTIONS(163),
    [anon_sym_xor] = ACTIONS(163),
    [anon_sym_CARET_CARET] = ACTIONS(163),
    [anon_sym_or] = ACTIONS(163),
    [anon_sym_PIPE_PIPE] = ACTIONS(163),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(163),
    [anon_sym_LPAREN] = ACTIONS(163),
    [anon_sym_RPAREN] = ACTIONS(163),
    [anon_sym_lookup_json_string] = ACTIONS(163),
    [anon_sym_lower] = ACTIONS(163),
    [anon_sym_regex_replace] = ACTIONS(163),
    [anon_sym_remove_bytes] = ACTIONS(163),
    [anon_sym_to_string] = ACTIONS(163),
    [anon_sym_upper] = ACTIONS(163),
    [anon_sym_url_decode] = ACTIONS(163),
    [anon_sym_uuidv4] = ACTIONS(163),
    [anon_sym_len] = ACTIONS(163),
    [anon_sym_ends_with] = ACTIONS(163),
    [anon_sym_starts_with] = ACTIONS(163),
    [anon_sym_true] = ACTIONS(163),
    [anon_sym_false] = ACTIONS(163),
    [anon_sym_not] = ACTIONS(163),
    [anon_sym_BANG] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(163),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(163),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(165),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(163),
    [anon_sym_ip_DOTsrc] = ACTIONS(165),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(163),
    [anon_sym_http_DOTcookie] = ACTIONS(163),
    [anon_sym_http_DOThost] = ACTIONS(163),
    [anon_sym_http_DOTreferer] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(163),
    [anon_sym_http_DOTuser_agent] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(163),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(163),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(163),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(163),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(163),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(163),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(163),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(163),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(163),
    [anon_sym_ssl] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(163),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(163),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(163),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(163),
  },
  [34] = {
    [ts_builtin_sym_end] = ACTIONS(167),
    [anon_sym_AMP_AMP] = ACTIONS(167),
    [anon_sym_and] = ACTIONS(167),
    [anon_sym_xor] = ACTIONS(167),
    [anon_sym_CARET_CARET] = ACTIONS(167),
    [anon_sym_or] = ACTIONS(167),
    [anon_sym_PIPE_PIPE] = ACTIONS(167),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(167),
    [anon_sym_LPAREN] = ACTIONS(167),
    [anon_sym_RPAREN] = ACTIONS(167),
    [anon_sym_lookup_json_string] = ACTIONS(167),
    [anon_sym_lower] = ACTIONS(167),
    [anon_sym_regex_replace] = ACTIONS(167),
    [anon_sym_remove_bytes] = ACTIONS(167),
    [anon_sym_to_string] = ACTIONS(167),
    [anon_sym_upper] = ACTIONS(167),
    [anon_sym_url_decode] = ACTIONS(167),
    [anon_sym_uuidv4] = ACTIONS(167),
    [anon_sym_len] = ACTIONS(167),
    [anon_sym_ends_with] = ACTIONS(167),
    [anon_sym_starts_with] = ACTIONS(167),
    [anon_sym_true] = ACTIONS(167),
    [anon_sym_false] = ACTIONS(167),
    [anon_sym_not] = ACTIONS(167),
    [anon_sym_BANG] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(167),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(167),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(167),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(167),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(167),
    [anon_sym_ip_DOTsrc] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(167),
    [anon_sym_http_DOTcookie] = ACTIONS(167),
    [anon_sym_http_DOThost] = ACTIONS(167),
    [anon_sym_http_DOTreferer] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(167),
    [anon_sym_http_DOTuser_agent] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(167),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(167),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(167),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(167),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(167),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(167),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(167),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(167),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(167),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(167),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(167),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(167),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(167),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(167),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(167),
    [anon_sym_ssl] = ACTIONS(167),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(167),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(167),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(167),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(167),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(167),
  },
  [35] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [36] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [37] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [38] = {
    [ts_builtin_sym_end] = ACTIONS(171),
    [anon_sym_AMP_AMP] = ACTIONS(171),
    [anon_sym_and] = ACTIONS(171),
    [anon_sym_xor] = ACTIONS(171),
    [anon_sym_CARET_CARET] = ACTIONS(171),
    [anon_sym_or] = ACTIONS(171),
    [anon_sym_PIPE_PIPE] = ACTIONS(171),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(171),
    [anon_sym_LPAREN] = ACTIONS(171),
    [anon_sym_RPAREN] = ACTIONS(171),
    [anon_sym_lookup_json_string] = ACTIONS(171),
    [anon_sym_lower] = ACTIONS(171),
    [anon_sym_regex_replace] = ACTIONS(171),
    [anon_sym_remove_bytes] = ACTIONS(171),
    [anon_sym_to_string] = ACTIONS(171),
    [anon_sym_upper] = ACTIONS(171),
    [anon_sym_url_decode] = ACTIONS(171),
    [anon_sym_uuidv4] = ACTIONS(171),
    [anon_sym_len] = ACTIONS(171),
    [anon_sym_ends_with] = ACTIONS(171),
    [anon_sym_starts_with] = ACTIONS(171),
    [anon_sym_true] = ACTIONS(171),
    [anon_sym_false] = ACTIONS(171),
    [anon_sym_not] = ACTIONS(171),
    [anon_sym_BANG] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(171),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(171),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(171),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(173),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(171),
    [anon_sym_ip_DOTsrc] = ACTIONS(173),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(171),
    [anon_sym_http_DOTcookie] = ACTIONS(171),
    [anon_sym_http_DOThost] = ACTIONS(171),
    [anon_sym_http_DOTreferer] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(171),
    [anon_sym_http_DOTuser_agent] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(171),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(171),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(171),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(171),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(171),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(171),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(171),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(171),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(171),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(171),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(171),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(171),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(171),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(171),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(171),
    [anon_sym_ssl] = ACTIONS(171),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(171),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(171),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(171),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(171),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(171),
  },
  [39] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [40] = {
    [ts_builtin_sym_end] = ACTIONS(175),
    [anon_sym_AMP_AMP] = ACTIONS(175),
    [anon_sym_and] = ACTIONS(175),
    [anon_sym_xor] = ACTIONS(175),
    [anon_sym_CARET_CARET] = ACTIONS(175),
    [anon_sym_or] = ACTIONS(175),
    [anon_sym_PIPE_PIPE] = ACTIONS(175),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(175),
    [anon_sym_LPAREN] = ACTIONS(175),
    [anon_sym_RPAREN] = ACTIONS(175),
    [anon_sym_lookup_json_string] = ACTIONS(175),
    [anon_sym_lower] = ACTIONS(175),
    [anon_sym_regex_replace] = ACTIONS(175),
    [anon_sym_remove_bytes] = ACTIONS(175),
    [anon_sym_to_string] = ACTIONS(175),
    [anon_sym_upper] = ACTIONS(175),
    [anon_sym_url_decode] = ACTIONS(175),
    [anon_sym_uuidv4] = ACTIONS(175),
    [anon_sym_len] = ACTIONS(175),
    [anon_sym_ends_with] = ACTIONS(175),
    [anon_sym_starts_with] = ACTIONS(175),
    [anon_sym_true] = ACTIONS(175),
    [anon_sym_false] = ACTIONS(175),
    [anon_sym_not] = ACTIONS(175),
    [anon_sym_BANG] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(175),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(175),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(175),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(175),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(175),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(177),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(175),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(175),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(175),
    [anon_sym_ip_DOTsrc] = ACTIONS(177),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(175),
    [anon_sym_http_DOTcookie] = ACTIONS(175),
    [anon_sym_http_DOThost] = ACTIONS(175),
    [anon_sym_http_DOTreferer] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(175),
    [anon_sym_http_DOTuser_agent] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(175),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(175),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(175),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(175),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(175),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(175),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(175),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(175),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(175),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(175),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(175),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(175),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(175),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(175),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(175),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(175),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(175),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(175),
    [anon_sym_ssl] = ACTIONS(175),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(175),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(175),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(175),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(175),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(175),
  },
  [41] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [42] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [43] = {
    [ts_builtin_sym_end] = ACTIONS(179),
    [anon_sym_AMP_AMP] = ACTIONS(179),
    [anon_sym_and] = ACTIONS(179),
    [anon_sym_xor] = ACTIONS(179),
    [anon_sym_CARET_CARET] = ACTIONS(179),
    [anon_sym_or] = ACTIONS(179),
    [anon_sym_PIPE_PIPE] = ACTIONS(179),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(179),
    [anon_sym_LPAREN] = ACTIONS(179),
    [anon_sym_RPAREN] = ACTIONS(179),
    [anon_sym_lookup_json_string] = ACTIONS(179),
    [anon_sym_lower] = ACTIONS(179),
    [anon_sym_regex_replace] = ACTIONS(179),
    [anon_sym_remove_bytes] = ACTIONS(179),
    [anon_sym_to_string] = ACTIONS(179),
    [anon_sym_upper] = ACTIONS(179),
    [anon_sym_url_decode] = ACTIONS(179),
    [anon_sym_uuidv4] = ACTIONS(179),
    [anon_sym_len] = ACTIONS(179),
    [anon_sym_ends_with] = ACTIONS(179),
    [anon_sym_starts_with] = ACTIONS(179),
    [anon_sym_true] = ACTIONS(179),
    [anon_sym_false] = ACTIONS(179),
    [anon_sym_not] = ACTIONS(179),
    [anon_sym_BANG] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(179),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(179),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(179),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(179),
    [anon_sym_ip_DOTsrc] = ACTIONS(181),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(179),
    [anon_sym_http_DOThost] = ACTIONS(179),
    [anon_sym_http_DOTreferer] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(179),
    [anon_sym_http_DOTuser_agent] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(179),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(179),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(179),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(179),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(179),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(179),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(179),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(179),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(179),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(179),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(179),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(179),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(179),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(179),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(179),
    [anon_sym_ssl] = ACTIONS(179),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(179),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(179),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(179),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(179),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(179),
  },
  [44] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [45] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [46] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [47] = {
    [ts_builtin_sym_end] = ACTIONS(183),
    [anon_sym_AMP_AMP] = ACTIONS(183),
    [anon_sym_and] = ACTIONS(183),
    [anon_sym_xor] = ACTIONS(183),
    [anon_sym_CARET_CARET] = ACTIONS(183),
    [anon_sym_or] = ACTIONS(183),
    [anon_sym_PIPE_PIPE] = ACTIONS(183),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(183),
    [anon_sym_LPAREN] = ACTIONS(183),
    [anon_sym_RPAREN] = ACTIONS(183),
    [anon_sym_lookup_json_string] = ACTIONS(183),
    [anon_sym_lower] = ACTIONS(183),
    [anon_sym_regex_replace] = ACTIONS(183),
    [anon_sym_remove_bytes] = ACTIONS(183),
    [anon_sym_to_string] = ACTIONS(183),
    [anon_sym_upper] = ACTIONS(183),
    [anon_sym_url_decode] = ACTIONS(183),
    [anon_sym_uuidv4] = ACTIONS(183),
    [anon_sym_len] = ACTIONS(183),
    [anon_sym_ends_with] = ACTIONS(183),
    [anon_sym_starts_with] = ACTIONS(183),
    [anon_sym_true] = ACTIONS(183),
    [anon_sym_false] = ACTIONS(183),
    [anon_sym_not] = ACTIONS(183),
    [anon_sym_BANG] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(183),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(183),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(183),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(183),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(183),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(185),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(183),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(183),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(183),
    [anon_sym_ip_DOTsrc] = ACTIONS(185),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(183),
    [anon_sym_http_DOTcookie] = ACTIONS(183),
    [anon_sym_http_DOThost] = ACTIONS(183),
    [anon_sym_http_DOTreferer] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(183),
    [anon_sym_http_DOTuser_agent] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(183),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(183),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(183),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(183),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(183),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(183),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(183),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(183),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(183),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(183),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(183),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(183),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(183),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(183),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(183),
    [anon_sym_ssl] = ACTIONS(183),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(183),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(183),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(183),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(183),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(183),
  },
  [48] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [49] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [50] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [51] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [52] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [53] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(133),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(133),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(133),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(133),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [54] = {
    [ts_builtin_sym_end] = ACTIONS(155),
    [anon_sym_AMP_AMP] = ACTIONS(155),
    [anon_sym_and] = ACTIONS(155),
    [anon_sym_xor] = ACTIONS(155),
    [anon_sym_CARET_CARET] = ACTIONS(155),
    [anon_sym_or] = ACTIONS(155),
    [anon_sym_PIPE_PIPE] = ACTIONS(155),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(155),
    [anon_sym_LPAREN] = ACTIONS(155),
    [anon_sym_RPAREN] = ACTIONS(155),
    [anon_sym_lookup_json_string] = ACTIONS(155),
    [anon_sym_lower] = ACTIONS(155),
    [anon_sym_regex_replace] = ACTIONS(155),
    [anon_sym_remove_bytes] = ACTIONS(155),
    [anon_sym_to_string] = ACTIONS(155),
    [anon_sym_upper] = ACTIONS(155),
    [anon_sym_url_decode] = ACTIONS(155),
    [anon_sym_uuidv4] = ACTIONS(155),
    [anon_sym_len] = ACTIONS(155),
    [anon_sym_ends_with] = ACTIONS(155),
    [anon_sym_starts_with] = ACTIONS(155),
    [anon_sym_true] = ACTIONS(155),
    [anon_sym_false] = ACTIONS(155),
    [anon_sym_not] = ACTIONS(155),
    [anon_sym_BANG] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(155),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(155),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(155),
    [anon_sym_ip_DOTsrc] = ACTIONS(157),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(155),
    [anon_sym_http_DOTcookie] = ACTIONS(155),
    [anon_sym_http_DOThost] = ACTIONS(155),
    [anon_sym_http_DOTreferer] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(155),
    [anon_sym_http_DOTuser_agent] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(155),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(155),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(155),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(155),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(155),
    [anon_sym_ssl] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(155),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(155),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(155),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(155),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(155),
  },
  [55] = {
    [ts_builtin_sym_end] = ACTIONS(187),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(191),
    [anon_sym_xor] = ACTIONS(193),
    [anon_sym_CARET_CARET] = ACTIONS(195),
    [anon_sym_or] = ACTIONS(187),
    [anon_sym_PIPE_PIPE] = ACTIONS(187),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(187),
    [anon_sym_LPAREN] = ACTIONS(187),
    [anon_sym_RPAREN] = ACTIONS(187),
    [anon_sym_lookup_json_string] = ACTIONS(187),
    [anon_sym_lower] = ACTIONS(187),
    [anon_sym_regex_replace] = ACTIONS(187),
    [anon_sym_remove_bytes] = ACTIONS(187),
    [anon_sym_to_string] = ACTIONS(187),
    [anon_sym_upper] = ACTIONS(187),
    [anon_sym_url_decode] = ACTIONS(187),
    [anon_sym_uuidv4] = ACTIONS(187),
    [anon_sym_len] = ACTIONS(187),
    [anon_sym_ends_with] = ACTIONS(187),
    [anon_sym_starts_with] = ACTIONS(187),
    [anon_sym_true] = ACTIONS(187),
    [anon_sym_false] = ACTIONS(187),
    [anon_sym_not] = ACTIONS(187),
    [anon_sym_BANG] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(187),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_http_DOTuser_agent] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(187),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(187),
    [anon_sym_ssl] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(187),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(187),
  },
  [56] = {
    [ts_builtin_sym_end] = ACTIONS(187),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(191),
    [anon_sym_xor] = ACTIONS(193),
    [anon_sym_CARET_CARET] = ACTIONS(195),
    [anon_sym_or] = ACTIONS(187),
    [anon_sym_PIPE_PIPE] = ACTIONS(187),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(187),
    [anon_sym_LPAREN] = ACTIONS(187),
    [anon_sym_RPAREN] = ACTIONS(187),
    [anon_sym_lookup_json_string] = ACTIONS(187),
    [anon_sym_lower] = ACTIONS(187),
    [anon_sym_regex_replace] = ACTIONS(187),
    [anon_sym_remove_bytes] = ACTIONS(187),
    [anon_sym_to_string] = ACTIONS(187),
    [anon_sym_upper] = ACTIONS(187),
    [anon_sym_url_decode] = ACTIONS(187),
    [anon_sym_uuidv4] = ACTIONS(187),
    [anon_sym_len] = ACTIONS(187),
    [anon_sym_ends_with] = ACTIONS(187),
    [anon_sym_starts_with] = ACTIONS(187),
    [anon_sym_true] = ACTIONS(187),
    [anon_sym_false] = ACTIONS(187),
    [anon_sym_not] = ACTIONS(187),
    [anon_sym_BANG] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(187),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_http_DOTuser_agent] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(187),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(187),
    [anon_sym_ssl] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(187),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(187),
  },
  [57] = {
    [ts_builtin_sym_end] = ACTIONS(187),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(191),
    [anon_sym_xor] = ACTIONS(187),
    [anon_sym_CARET_CARET] = ACTIONS(187),
    [anon_sym_or] = ACTIONS(187),
    [anon_sym_PIPE_PIPE] = ACTIONS(187),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(187),
    [anon_sym_LPAREN] = ACTIONS(187),
    [anon_sym_RPAREN] = ACTIONS(187),
    [anon_sym_lookup_json_string] = ACTIONS(187),
    [anon_sym_lower] = ACTIONS(187),
    [anon_sym_regex_replace] = ACTIONS(187),
    [anon_sym_remove_bytes] = ACTIONS(187),
    [anon_sym_to_string] = ACTIONS(187),
    [anon_sym_upper] = ACTIONS(187),
    [anon_sym_url_decode] = ACTIONS(187),
    [anon_sym_uuidv4] = ACTIONS(187),
    [anon_sym_len] = ACTIONS(187),
    [anon_sym_ends_with] = ACTIONS(187),
    [anon_sym_starts_with] = ACTIONS(187),
    [anon_sym_true] = ACTIONS(187),
    [anon_sym_false] = ACTIONS(187),
    [anon_sym_not] = ACTIONS(187),
    [anon_sym_BANG] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(187),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_http_DOTuser_agent] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(187),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(187),
    [anon_sym_ssl] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(187),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(187),
  },
  [58] = {
    [ts_builtin_sym_end] = ACTIONS(187),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(191),
    [anon_sym_xor] = ACTIONS(187),
    [anon_sym_CARET_CARET] = ACTIONS(187),
    [anon_sym_or] = ACTIONS(187),
    [anon_sym_PIPE_PIPE] = ACTIONS(187),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(187),
    [anon_sym_LPAREN] = ACTIONS(187),
    [anon_sym_RPAREN] = ACTIONS(187),
    [anon_sym_lookup_json_string] = ACTIONS(187),
    [anon_sym_lower] = ACTIONS(187),
    [anon_sym_regex_replace] = ACTIONS(187),
    [anon_sym_remove_bytes] = ACTIONS(187),
    [anon_sym_to_string] = ACTIONS(187),
    [anon_sym_upper] = ACTIONS(187),
    [anon_sym_url_decode] = ACTIONS(187),
    [anon_sym_uuidv4] = ACTIONS(187),
    [anon_sym_len] = ACTIONS(187),
    [anon_sym_ends_with] = ACTIONS(187),
    [anon_sym_starts_with] = ACTIONS(187),
    [anon_sym_true] = ACTIONS(187),
    [anon_sym_false] = ACTIONS(187),
    [anon_sym_not] = ACTIONS(187),
    [anon_sym_BANG] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(187),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_http_DOTuser_agent] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(187),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(187),
    [anon_sym_ssl] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(187),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(187),
  },
  [59] = {
    [ts_builtin_sym_end] = ACTIONS(187),
    [anon_sym_AMP_AMP] = ACTIONS(187),
    [anon_sym_and] = ACTIONS(187),
    [anon_sym_xor] = ACTIONS(187),
    [anon_sym_CARET_CARET] = ACTIONS(187),
    [anon_sym_or] = ACTIONS(187),
    [anon_sym_PIPE_PIPE] = ACTIONS(187),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(187),
    [anon_sym_LPAREN] = ACTIONS(187),
    [anon_sym_RPAREN] = ACTIONS(187),
    [anon_sym_lookup_json_string] = ACTIONS(187),
    [anon_sym_lower] = ACTIONS(187),
    [anon_sym_regex_replace] = ACTIONS(187),
    [anon_sym_remove_bytes] = ACTIONS(187),
    [anon_sym_to_string] = ACTIONS(187),
    [anon_sym_upper] = ACTIONS(187),
    [anon_sym_url_decode] = ACTIONS(187),
    [anon_sym_uuidv4] = ACTIONS(187),
    [anon_sym_len] = ACTIONS(187),
    [anon_sym_ends_with] = ACTIONS(187),
    [anon_sym_starts_with] = ACTIONS(187),
    [anon_sym_true] = ACTIONS(187),
    [anon_sym_false] = ACTIONS(187),
    [anon_sym_not] = ACTIONS(187),
    [anon_sym_BANG] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(187),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_http_DOTuser_agent] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(187),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(187),
    [anon_sym_ssl] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(187),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(187),
  },
  [60] = {
    [ts_builtin_sym_end] = ACTIONS(187),
    [anon_sym_AMP_AMP] = ACTIONS(187),
    [anon_sym_and] = ACTIONS(187),
    [anon_sym_xor] = ACTIONS(187),
    [anon_sym_CARET_CARET] = ACTIONS(187),
    [anon_sym_or] = ACTIONS(187),
    [anon_sym_PIPE_PIPE] = ACTIONS(187),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(187),
    [anon_sym_LPAREN] = ACTIONS(187),
    [anon_sym_RPAREN] = ACTIONS(187),
    [anon_sym_lookup_json_string] = ACTIONS(187),
    [anon_sym_lower] = ACTIONS(187),
    [anon_sym_regex_replace] = ACTIONS(187),
    [anon_sym_remove_bytes] = ACTIONS(187),
    [anon_sym_to_string] = ACTIONS(187),
    [anon_sym_upper] = ACTIONS(187),
    [anon_sym_url_decode] = ACTIONS(187),
    [anon_sym_uuidv4] = ACTIONS(187),
    [anon_sym_len] = ACTIONS(187),
    [anon_sym_ends_with] = ACTIONS(187),
    [anon_sym_starts_with] = ACTIONS(187),
    [anon_sym_true] = ACTIONS(187),
    [anon_sym_false] = ACTIONS(187),
    [anon_sym_not] = ACTIONS(187),
    [anon_sym_BANG] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(187),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_http_DOTuser_agent] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(187),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(187),
    [anon_sym_ssl] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(187),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(187),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(187),
  },
  [61] = {
    [ts_builtin_sym_end] = ACTIONS(199),
    [anon_sym_AMP_AMP] = ACTIONS(199),
    [anon_sym_and] = ACTIONS(199),
    [anon_sym_xor] = ACTIONS(199),
    [anon_sym_CARET_CARET] = ACTIONS(199),
    [anon_sym_or] = ACTIONS(199),
    [anon_sym_PIPE_PIPE] = ACTIONS(199),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(199),
    [anon_sym_LPAREN] = ACTIONS(199),
    [anon_sym_RPAREN] = ACTIONS(199),
    [anon_sym_lookup_json_string] = ACTIONS(199),
    [anon_sym_lower] = ACTIONS(199),
    [anon_sym_regex_replace] = ACTIONS(199),
    [anon_sym_remove_bytes] = ACTIONS(199),
    [anon_sym_to_string] = ACTIONS(199),
    [anon_sym_upper] = ACTIONS(199),
    [anon_sym_url_decode] = ACTIONS(199),
    [anon_sym_uuidv4] = ACTIONS(199),
    [anon_sym_len] = ACTIONS(199),
    [anon_sym_ends_with] = ACTIONS(199),
    [anon_sym_starts_with] = ACTIONS(199),
    [anon_sym_true] = ACTIONS(199),
    [anon_sym_false] = ACTIONS(199),
    [anon_sym_not] = ACTIONS(199),
    [anon_sym_BANG] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(199),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(199),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(199),
    [anon_sym_ip_DOTsrc] = ACTIONS(201),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(199),
    [anon_sym_http_DOTcookie] = ACTIONS(199),
    [anon_sym_http_DOThost] = ACTIONS(199),
    [anon_sym_http_DOTreferer] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(199),
    [anon_sym_http_DOTuser_agent] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(199),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(199),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(199),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(199),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(199),
    [anon_sym_ssl] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(199),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(199),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(199),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(199),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(199),
  },
  [62] = {
    [ts_builtin_sym_end] = ACTIONS(203),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(191),
    [anon_sym_xor] = ACTIONS(193),
    [anon_sym_CARET_CARET] = ACTIONS(195),
    [anon_sym_or] = ACTIONS(205),
    [anon_sym_PIPE_PIPE] = ACTIONS(207),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(203),
    [anon_sym_LPAREN] = ACTIONS(203),
    [anon_sym_lookup_json_string] = ACTIONS(203),
    [anon_sym_lower] = ACTIONS(203),
    [anon_sym_regex_replace] = ACTIONS(203),
    [anon_sym_remove_bytes] = ACTIONS(203),
    [anon_sym_to_string] = ACTIONS(203),
    [anon_sym_upper] = ACTIONS(203),
    [anon_sym_url_decode] = ACTIONS(203),
    [anon_sym_uuidv4] = ACTIONS(203),
    [anon_sym_len] = ACTIONS(203),
    [anon_sym_ends_with] = ACTIONS(203),
    [anon_sym_starts_with] = ACTIONS(203),
    [anon_sym_true] = ACTIONS(203),
    [anon_sym_false] = ACTIONS(203),
    [anon_sym_not] = ACTIONS(203),
    [anon_sym_BANG] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(203),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(203),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(203),
    [anon_sym_ip_DOTsrc] = ACTIONS(209),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(203),
    [anon_sym_http_DOTcookie] = ACTIONS(203),
    [anon_sym_http_DOThost] = ACTIONS(203),
    [anon_sym_http_DOTreferer] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(203),
    [anon_sym_http_DOTuser_agent] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(203),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(203),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(203),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(203),
    [anon_sym_ssl] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(203),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(203),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(203),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(203),
  },
  [63] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(211),
    [anon_sym_LPAREN] = ACTIONS(211),
    [anon_sym_lookup_json_string] = ACTIONS(211),
    [anon_sym_lower] = ACTIONS(211),
    [anon_sym_regex_replace] = ACTIONS(211),
    [anon_sym_remove_bytes] = ACTIONS(211),
    [anon_sym_to_string] = ACTIONS(211),
    [anon_sym_upper] = ACTIONS(211),
    [anon_sym_url_decode] = ACTIONS(211),
    [anon_sym_uuidv4] = ACTIONS(211),
    [anon_sym_len] = ACTIONS(211),
    [anon_sym_ends_with] = ACTIONS(211),
    [anon_sym_starts_with] = ACTIONS(211),
    [anon_sym_true] = ACTIONS(211),
    [anon_sym_false] = ACTIONS(211),
    [anon_sym_not] = ACTIONS(211),
    [anon_sym_BANG] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(211),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(211),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(211),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(211),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(211),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(213),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(211),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(211),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(211),
    [anon_sym_ip_DOTsrc] = ACTIONS(213),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(211),
    [anon_sym_http_DOTcookie] = ACTIONS(211),
    [anon_sym_http_DOThost] = ACTIONS(211),
    [anon_sym_http_DOTreferer] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(211),
    [anon_sym_http_DOTuser_agent] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(211),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(211),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(211),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(211),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(211),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(211),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(211),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(211),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(211),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(211),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(211),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(211),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(211),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(211),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(211),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(211),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(211),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(211),
    [anon_sym_ssl] = ACTIONS(211),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(211),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(211),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(211),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(211),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(211),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(217), 5,
      anon_sym_LT,
      anon_sym_GT,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(215), 56,
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
      anon_sym_concat,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      anon_sym_lookup_json_string,
      anon_sym_lower,
      anon_sym_regex_replace,
      anon_sym_remove_bytes,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_uuidv4,
      sym_number,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [69] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(221), 5,
      anon_sym_LT,
      anon_sym_GT,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(219), 56,
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
      anon_sym_concat,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      anon_sym_lookup_json_string,
      anon_sym_lower,
      anon_sym_regex_replace,
      anon_sym_remove_bytes,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_uuidv4,
      sym_number,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [138] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    ACTIONS(237), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(175), 1,
      sym_bytes_field,
    STATE(177), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    STATE(176), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [227] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(241), 1,
      anon_sym_concat,
    ACTIONS(244), 1,
      anon_sym_RPAREN,
    ACTIONS(246), 1,
      anon_sym_lookup_json_string,
    ACTIONS(252), 1,
      anon_sym_regex_replace,
    ACTIONS(255), 1,
      anon_sym_remove_bytes,
    ACTIONS(258), 1,
      anon_sym_to_string,
    ACTIONS(261), 1,
      anon_sym_uuidv4,
    ACTIONS(264), 1,
      sym_string,
    ACTIONS(273), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(276), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    STATE(67), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(270), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(249), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(279), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(267), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [316] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    ACTIONS(237), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(186), 1,
      sym_bytes_field,
    STATE(193), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    STATE(192), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [405] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(284), 1,
      anon_sym_RPAREN,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    STATE(67), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [494] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    ACTIONS(300), 1,
      anon_sym_RPAREN,
    STATE(67), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [583] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    ACTIONS(302), 1,
      anon_sym_RPAREN,
    STATE(67), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [672] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    ACTIONS(304), 1,
      anon_sym_RPAREN,
    STATE(67), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [761] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    STATE(69), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [847] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    STATE(72), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [933] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    STATE(71), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1019] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    ACTIONS(306), 1,
      sym_string,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(206), 1,
      sym__string_array_expansion,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    STATE(203), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1105] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(282), 1,
      anon_sym_concat,
    ACTIONS(286), 1,
      anon_sym_lookup_json_string,
    ACTIONS(290), 1,
      anon_sym_regex_replace,
    ACTIONS(292), 1,
      anon_sym_remove_bytes,
    ACTIONS(294), 1,
      anon_sym_to_string,
    ACTIONS(296), 1,
      anon_sym_uuidv4,
    ACTIONS(298), 1,
      sym_string,
    STATE(70), 1,
      aux_sym_string_func_repeat1,
    STATE(270), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(83), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(271), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(288), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1191] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(179), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    STATE(178), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1274] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(136), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(145), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1357] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(200), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    STATE(198), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1440] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(197), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    STATE(196), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1523] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(174), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(161), 2,
      sym__string_array,
      sym_array_string_field,
    STATE(173), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(39), 25,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
  [1606] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(310), 1,
      anon_sym_COMMA,
    ACTIONS(312), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(308), 40,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_lookup_json_string,
      anon_sym_lower,
      anon_sym_regex_replace,
      anon_sym_remove_bytes,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_uuidv4,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1660] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(316), 1,
      anon_sym_COMMA,
    ACTIONS(318), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(314), 40,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_lookup_json_string,
      anon_sym_lower,
      anon_sym_regex_replace,
      anon_sym_remove_bytes,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_uuidv4,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1714] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(322), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(320), 40,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_lookup_json_string,
      anon_sym_lower,
      anon_sym_regex_replace,
      anon_sym_remove_bytes,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_uuidv4,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1765] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(326), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(324), 40,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_lookup_json_string,
      anon_sym_lower,
      anon_sym_regex_replace,
      anon_sym_remove_bytes,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_uuidv4,
      sym_string,
      anon_sym_http_DOTcookie,
      anon_sym_http_DOThost,
      anon_sym_http_DOTreferer,
      anon_sym_http_DOTrequest_DOTfull_uri,
      anon_sym_http_DOTrequest_DOTmethod,
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
      anon_sym_http_DOTrequest_DOTcookies,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1816] = 12,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(33), 1,
      anon_sym_cf_DOTwaf_DOTscore,
    ACTIONS(328), 1,
      anon_sym_len,
    STATE(155), 1,
      sym__bool_array,
    STATE(156), 1,
      sym__number_array,
    STATE(180), 1,
      sym_ip_field,
    ACTIONS(37), 2,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
    ACTIONS(330), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(181), 2,
      sym__numberlike_field,
      sym_number_field,
    STATE(182), 2,
      sym__boollike_field,
      sym_bool_field,
    ACTIONS(49), 8,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
      anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
    ACTIONS(31), 9,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
      anon_sym_ip_DOTgeoip_DOTasnum,
      anon_sym_cf_DOTbot_management_DOTscore,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTthreat_score,
      anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
      anon_sym_cf_DOTwaf_DOTscore_DOTxss,
      anon_sym_cf_DOTwaf_DOTscore_DOTrce,
  [1872] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(301), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1920] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(276), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1968] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(197), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2016] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(193), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2064] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(206), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2112] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(143), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2160] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(300), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2208] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(136), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2256] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(274), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2304] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(309), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2352] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(275), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2400] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(200), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2448] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(302), 1,
      sym__string_array_expansion,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2496] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(225), 1,
      anon_sym_lookup_json_string,
    ACTIONS(229), 1,
      anon_sym_regex_replace,
    ACTIONS(231), 1,
      anon_sym_remove_bytes,
    ACTIONS(233), 1,
      anon_sym_to_string,
    ACTIONS(235), 1,
      anon_sym_uuidv4,
    STATE(179), 1,
      sym__string_array_expansion,
    STATE(202), 1,
      sym_map_string_array_field,
    STATE(214), 2,
      sym__string_array,
      sym_array_string_field,
    ACTIONS(227), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(239), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [2544] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(334), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(332), 14,
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
  [2568] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(338), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(336), 14,
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
  [2592] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(342), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(340), 14,
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
  [2616] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(346), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(344), 14,
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
  [2640] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(350), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(348), 14,
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
  [2664] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(354), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(352), 14,
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
  [2688] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(354), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(352), 14,
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
  [2712] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(354), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(352), 14,
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
  [2736] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(358), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(356), 14,
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
  [2760] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(362), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(360), 14,
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
  [2784] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(366), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(364), 14,
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
  [2808] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(370), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(368), 14,
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
  [2832] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(372), 1,
      anon_sym_in,
    ACTIONS(374), 1,
      anon_sym_eq,
    ACTIONS(376), 1,
      anon_sym_ne,
    ACTIONS(378), 1,
      anon_sym_lt,
    ACTIONS(380), 1,
      anon_sym_le,
    ACTIONS(382), 1,
      anon_sym_gt,
    ACTIONS(384), 1,
      anon_sym_ge,
    ACTIONS(386), 1,
      anon_sym_EQ_EQ,
    ACTIONS(388), 1,
      anon_sym_BANG_EQ,
    ACTIONS(390), 1,
      anon_sym_LT,
    ACTIONS(392), 1,
      anon_sym_LT_EQ,
    ACTIONS(394), 1,
      anon_sym_GT,
    ACTIONS(396), 1,
      anon_sym_GT_EQ,
    ACTIONS(398), 1,
      anon_sym_contains,
    ACTIONS(400), 1,
      anon_sym_matches,
    ACTIONS(402), 1,
      anon_sym_TILDE,
  [2884] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(406), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(404), 12,
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
  [2906] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(410), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(408), 12,
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
  [2928] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(414), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(412), 11,
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
  [2949] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(416), 1,
      anon_sym_in,
    ACTIONS(418), 1,
      anon_sym_eq,
    ACTIONS(420), 1,
      anon_sym_ne,
    ACTIONS(422), 1,
      anon_sym_lt,
    ACTIONS(424), 1,
      anon_sym_le,
    ACTIONS(426), 1,
      anon_sym_gt,
    ACTIONS(428), 1,
      anon_sym_ge,
    ACTIONS(430), 1,
      anon_sym_EQ_EQ,
    ACTIONS(432), 1,
      anon_sym_BANG_EQ,
    ACTIONS(434), 1,
      anon_sym_LT,
    ACTIONS(436), 1,
      anon_sym_LT_EQ,
    ACTIONS(438), 1,
      anon_sym_GT,
    ACTIONS(440), 1,
      anon_sym_GT_EQ,
  [2992] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(444), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(442), 11,
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
  [3013] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(448), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(446), 11,
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
  [3034] = 8,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(189), 1,
      anon_sym_AMP_AMP,
    ACTIONS(191), 1,
      anon_sym_and,
    ACTIONS(193), 1,
      anon_sym_xor,
    ACTIONS(195), 1,
      anon_sym_CARET_CARET,
    ACTIONS(205), 1,
      anon_sym_or,
    ACTIONS(207), 1,
      anon_sym_PIPE_PIPE,
    ACTIONS(450), 1,
      anon_sym_RPAREN,
  [3059] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(452), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [3071] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(454), 1,
      anon_sym_RBRACE,
    ACTIONS(456), 1,
      sym_ipv4,
    STATE(123), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [3086] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(459), 1,
      anon_sym_in,
    ACTIONS(461), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [3099] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(328), 1,
      anon_sym_len,
    STATE(215), 1,
      sym__number_array,
    STATE(216), 1,
      sym__bool_array,
    ACTIONS(330), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
  [3116] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(328), 1,
      anon_sym_len,
    STATE(283), 1,
      sym__number_array,
    STATE(284), 1,
      sym__bool_array,
    ACTIONS(330), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
  [3133] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(463), 1,
      anon_sym_RBRACE,
    ACTIONS(465), 1,
      sym_ipv4,
    STATE(123), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [3148] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(467), 1,
      anon_sym_RPAREN,
    STATE(132), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(469), 2,
      sym_number,
      sym_string,
  [3162] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(465), 1,
      sym_ipv4,
    STATE(127), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [3174] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(471), 1,
      anon_sym_RPAREN,
    STATE(132), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(469), 2,
      sym_number,
      sym_string,
  [3188] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(473), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3198] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(475), 1,
      anon_sym_RPAREN,
    STATE(132), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(477), 2,
      sym_number,
      sym_string,
  [3212] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3222] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(482), 1,
      anon_sym_RPAREN,
    STATE(132), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(469), 2,
      sym_number,
      sym_string,
  [3236] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(484), 1,
      anon_sym_COMMA,
    ACTIONS(486), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3248] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(128), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(469), 2,
      sym_number,
      sym_string,
  [3259] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      anon_sym_RBRACE,
    ACTIONS(490), 1,
      sym_number,
    STATE(137), 1,
      aux_sym_number_set_repeat1,
  [3272] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(475), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3281] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(493), 1,
      anon_sym_LBRACE,
    ACTIONS(495), 1,
      sym_ip_list,
    STATE(34), 1,
      sym_ip_set,
  [3294] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(465), 1,
      sym_ipv4,
    STATE(38), 2,
      sym__ip,
      sym_ip_range,
  [3305] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(497), 1,
      anon_sym_RBRACE,
    ACTIONS(499), 1,
      sym_string,
    STATE(144), 1,
      aux_sym_string_set_repeat1,
  [3318] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(501), 1,
      anon_sym_RBRACE,
    ACTIONS(503), 1,
      sym_number,
    STATE(137), 1,
      aux_sym_number_set_repeat1,
  [3331] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(130), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(469), 2,
      sym_number,
      sym_string,
  [3342] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(505), 1,
      anon_sym_RBRACE,
    ACTIONS(507), 1,
      sym_string,
    STATE(144), 1,
      aux_sym_string_set_repeat1,
  [3355] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(134), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(469), 2,
      sym_number,
      sym_string,
  [3366] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(512), 1,
      anon_sym_LBRACK,
  [3376] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(512), 1,
      anon_sym_LBRACK,
  [3386] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_LBRACE,
    STATE(54), 1,
      sym_number_set,
  [3396] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(516), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(518), 1,
      anon_sym_LBRACK,
  [3406] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(522), 1,
      anon_sym_LBRACK,
  [3416] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(526), 1,
      anon_sym_LBRACK,
  [3426] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      anon_sym_LBRACE,
    STATE(29), 1,
      sym_string_set,
  [3436] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(530), 1,
      sym_string,
    ACTIONS(532), 1,
      anon_sym_STAR,
  [3446] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(534), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(536), 1,
      anon_sym_LBRACK,
  [3456] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(540), 1,
      anon_sym_LBRACK,
  [3466] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(544), 1,
      anon_sym_LBRACK,
  [3476] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(546), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [3484] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(548), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(550), 1,
      anon_sym_LBRACK,
  [3494] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(552), 1,
      sym_string,
    STATE(141), 1,
      aux_sym_string_set_repeat1,
  [3504] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(554), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(556), 1,
      anon_sym_LBRACK,
  [3514] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(560), 1,
      anon_sym_LBRACK,
  [3524] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(564), 1,
      anon_sym_LBRACK,
  [3534] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(568), 1,
      anon_sym_LBRACK,
  [3544] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(572), 1,
      anon_sym_LBRACK,
  [3554] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(574), 1,
      sym_number,
    STATE(142), 1,
      aux_sym_number_set_repeat1,
  [3564] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(576), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(578), 1,
      anon_sym_LBRACK,
  [3574] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(580), 1,
      sym_string,
  [3581] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(582), 1,
      anon_sym_RBRACK,
  [3588] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(584), 1,
      anon_sym_RBRACK,
  [3595] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(586), 1,
      anon_sym_RBRACK,
  [3602] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(588), 1,
      anon_sym_RBRACK,
  [3609] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(590), 1,
      anon_sym_LPAREN,
  [3616] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(592), 1,
      anon_sym_COMMA,
  [3623] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(594), 1,
      anon_sym_COMMA,
  [3630] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(596), 1,
      anon_sym_RPAREN,
  [3637] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(598), 1,
      anon_sym_RPAREN,
  [3644] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(600), 1,
      anon_sym_RPAREN,
  [3651] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      anon_sym_RPAREN,
  [3658] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(604), 1,
      anon_sym_RPAREN,
  [3665] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      anon_sym_RPAREN,
  [3672] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(608), 1,
      anon_sym_RPAREN,
  [3679] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(610), 1,
      anon_sym_RPAREN,
  [3686] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(612), 1,
      anon_sym_LPAREN,
  [3693] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(614), 1,
      anon_sym_LPAREN,
  [3700] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(548), 1,
      anon_sym_LBRACK,
  [3707] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(616), 1,
      anon_sym_COMMA,
  [3714] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(618), 1,
      sym_string,
  [3721] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(620), 1,
      sym_string,
  [3728] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(622), 1,
      sym_string,
  [3735] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(624), 1,
      sym_string,
  [3742] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(626), 1,
      sym_string,
  [3749] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(628), 1,
      anon_sym_COMMA,
  [3756] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(630), 1,
      anon_sym_COMMA,
  [3763] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(632), 1,
      anon_sym_RPAREN,
  [3770] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(634), 1,
      anon_sym_RPAREN,
  [3777] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(636), 1,
      anon_sym_COMMA,
  [3784] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(638), 1,
      anon_sym_COMMA,
  [3791] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(640), 1,
      anon_sym_RPAREN,
  [3798] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(576), 1,
      anon_sym_LBRACK,
  [3805] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(642), 1,
      anon_sym_RPAREN,
  [3812] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_LBRACK,
  [3819] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(644), 1,
      anon_sym_LBRACK,
  [3826] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(646), 1,
      anon_sym_COMMA,
  [3833] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(648), 1,
      sym_string,
  [3840] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(650), 1,
      sym_string,
  [3847] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(652), 1,
      anon_sym_COMMA,
  [3854] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(654), 1,
      anon_sym_COMMA,
  [3861] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(656), 1,
      anon_sym_LPAREN,
  [3868] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(658), 1,
      anon_sym_LPAREN,
  [3875] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(660), 1,
      anon_sym_LPAREN,
  [3882] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(662), 1,
      anon_sym_LPAREN,
  [3889] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(664), 1,
      aux_sym_ip_range_token1,
  [3896] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      anon_sym_LBRACK,
  [3903] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3910] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(666), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3917] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(668), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3924] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(670), 1,
      anon_sym_LPAREN,
  [3931] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(672), 1,
      anon_sym_LPAREN,
  [3938] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(674), 1,
      anon_sym_LPAREN,
  [3945] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(676), 1,
      sym_string,
  [3952] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(678), 1,
      sym_number,
  [3959] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(680), 1,
      anon_sym_RBRACK,
  [3966] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(682), 1,
      sym_number,
  [3973] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      anon_sym_LBRACK,
  [3980] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(684), 1,
      sym_number,
  [3987] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(686), 1,
      sym_string,
  [3994] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(688), 1,
      anon_sym_COMMA,
  [4001] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(690), 1,
      anon_sym_COMMA,
  [4008] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(692), 1,
      anon_sym_RPAREN,
  [4015] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(694), 1,
      anon_sym_RPAREN,
  [4022] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(696), 1,
      anon_sym_RPAREN,
  [4029] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK,
  [4036] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK,
  [4043] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(698), 1,
      anon_sym_RPAREN,
  [4050] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(700), 1,
      anon_sym_RPAREN,
  [4057] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(702), 1,
      sym_string,
  [4064] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(704), 1,
      sym_string,
  [4071] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(706), 1,
      sym_string,
  [4078] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(708), 1,
      sym_string,
  [4085] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(710), 1,
      sym_string,
  [4092] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(712), 1,
      sym_string,
  [4099] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(714), 1,
      sym_string,
  [4106] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(716), 1,
      sym_string,
  [4113] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(718), 1,
      sym_string,
  [4120] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(720), 1,
      sym_string,
  [4127] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(722), 1,
      sym_string,
  [4134] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(516), 1,
      anon_sym_LBRACK,
  [4141] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(724), 1,
      sym_string,
  [4148] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(726), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [4155] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(728), 1,
      sym_string,
  [4162] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(730), 1,
      sym_string,
  [4169] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 1,
      anon_sym_LBRACK,
  [4176] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(732), 1,
      sym_string,
  [4183] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(734), 1,
      sym_number,
  [4190] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LBRACK,
  [4197] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(736), 1,
      sym_number,
  [4204] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(738), 1,
      sym_number,
  [4211] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(740), 1,
      anon_sym_RPAREN,
  [4218] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(742), 1,
      anon_sym_RPAREN,
  [4225] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(534), 1,
      anon_sym_LBRACK,
  [4232] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(744), 1,
      sym_number,
  [4239] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(746), 1,
      sym_number,
  [4246] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(748), 1,
      sym_number,
  [4253] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(750), 1,
      sym_number,
  [4260] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(752), 1,
      sym_number,
  [4267] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(754), 1,
      sym_number,
  [4274] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(756), 1,
      sym_number,
  [4281] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(758), 1,
      sym_number,
  [4288] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(760), 1,
      sym_number,
  [4295] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(762), 1,
      anon_sym_LBRACK,
  [4302] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(764), 1,
      anon_sym_LBRACK,
  [4309] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(766), 1,
      anon_sym_LBRACK,
  [4316] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(768), 1,
      anon_sym_LBRACK,
  [4323] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(770), 1,
      anon_sym_RPAREN,
  [4330] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(772), 1,
      anon_sym_RPAREN,
  [4337] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(774), 1,
      anon_sym_RPAREN,
  [4344] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(776), 1,
      anon_sym_RBRACK,
  [4351] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(778), 1,
      ts_builtin_sym_end,
  [4358] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(554), 1,
      anon_sym_LBRACK,
  [4365] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(780), 1,
      anon_sym_LBRACK,
  [4372] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(782), 1,
      anon_sym_RPAREN,
  [4379] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(784), 1,
      anon_sym_RPAREN,
  [4386] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [4393] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [4400] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(786), 1,
      anon_sym_LPAREN,
  [4407] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(788), 1,
      anon_sym_RPAREN,
  [4414] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(790), 1,
      anon_sym_RPAREN,
  [4421] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(792), 1,
      anon_sym_RPAREN,
  [4428] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(794), 1,
      anon_sym_LPAREN,
  [4435] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(796), 1,
      anon_sym_LPAREN,
  [4442] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(798), 1,
      anon_sym_LPAREN,
  [4449] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(800), 1,
      anon_sym_LPAREN,
  [4456] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(802), 1,
      anon_sym_LPAREN,
  [4463] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(804), 1,
      anon_sym_LPAREN,
  [4470] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(806), 1,
      sym_string,
  [4477] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(808), 1,
      sym_string,
  [4484] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(810), 1,
      sym_string,
  [4491] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(812), 1,
      anon_sym_LPAREN,
  [4498] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(814), 1,
      anon_sym_LPAREN,
  [4505] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(816), 1,
      anon_sym_COMMA,
  [4512] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(818), 1,
      anon_sym_COMMA,
  [4519] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(820), 1,
      anon_sym_COMMA,
  [4526] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(822), 1,
      anon_sym_LPAREN,
  [4533] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(824), 1,
      anon_sym_LPAREN,
  [4540] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(826), 1,
      anon_sym_COMMA,
  [4547] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(828), 1,
      anon_sym_LPAREN,
  [4554] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(830), 1,
      anon_sym_LPAREN,
  [4561] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(832), 1,
      sym_string,
  [4568] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(834), 1,
      anon_sym_COMMA,
  [4575] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(836), 1,
      anon_sym_LPAREN,
  [4582] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(838), 1,
      anon_sym_LPAREN,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(64)] = 0,
  [SMALL_STATE(65)] = 69,
  [SMALL_STATE(66)] = 138,
  [SMALL_STATE(67)] = 227,
  [SMALL_STATE(68)] = 316,
  [SMALL_STATE(69)] = 405,
  [SMALL_STATE(70)] = 494,
  [SMALL_STATE(71)] = 583,
  [SMALL_STATE(72)] = 672,
  [SMALL_STATE(73)] = 761,
  [SMALL_STATE(74)] = 847,
  [SMALL_STATE(75)] = 933,
  [SMALL_STATE(76)] = 1019,
  [SMALL_STATE(77)] = 1105,
  [SMALL_STATE(78)] = 1191,
  [SMALL_STATE(79)] = 1274,
  [SMALL_STATE(80)] = 1357,
  [SMALL_STATE(81)] = 1440,
  [SMALL_STATE(82)] = 1523,
  [SMALL_STATE(83)] = 1606,
  [SMALL_STATE(84)] = 1660,
  [SMALL_STATE(85)] = 1714,
  [SMALL_STATE(86)] = 1765,
  [SMALL_STATE(87)] = 1816,
  [SMALL_STATE(88)] = 1872,
  [SMALL_STATE(89)] = 1920,
  [SMALL_STATE(90)] = 1968,
  [SMALL_STATE(91)] = 2016,
  [SMALL_STATE(92)] = 2064,
  [SMALL_STATE(93)] = 2112,
  [SMALL_STATE(94)] = 2160,
  [SMALL_STATE(95)] = 2208,
  [SMALL_STATE(96)] = 2256,
  [SMALL_STATE(97)] = 2304,
  [SMALL_STATE(98)] = 2352,
  [SMALL_STATE(99)] = 2400,
  [SMALL_STATE(100)] = 2448,
  [SMALL_STATE(101)] = 2496,
  [SMALL_STATE(102)] = 2544,
  [SMALL_STATE(103)] = 2568,
  [SMALL_STATE(104)] = 2592,
  [SMALL_STATE(105)] = 2616,
  [SMALL_STATE(106)] = 2640,
  [SMALL_STATE(107)] = 2664,
  [SMALL_STATE(108)] = 2688,
  [SMALL_STATE(109)] = 2712,
  [SMALL_STATE(110)] = 2736,
  [SMALL_STATE(111)] = 2760,
  [SMALL_STATE(112)] = 2784,
  [SMALL_STATE(113)] = 2808,
  [SMALL_STATE(114)] = 2832,
  [SMALL_STATE(115)] = 2884,
  [SMALL_STATE(116)] = 2906,
  [SMALL_STATE(117)] = 2928,
  [SMALL_STATE(118)] = 2949,
  [SMALL_STATE(119)] = 2992,
  [SMALL_STATE(120)] = 3013,
  [SMALL_STATE(121)] = 3034,
  [SMALL_STATE(122)] = 3059,
  [SMALL_STATE(123)] = 3071,
  [SMALL_STATE(124)] = 3086,
  [SMALL_STATE(125)] = 3099,
  [SMALL_STATE(126)] = 3116,
  [SMALL_STATE(127)] = 3133,
  [SMALL_STATE(128)] = 3148,
  [SMALL_STATE(129)] = 3162,
  [SMALL_STATE(130)] = 3174,
  [SMALL_STATE(131)] = 3188,
  [SMALL_STATE(132)] = 3198,
  [SMALL_STATE(133)] = 3212,
  [SMALL_STATE(134)] = 3222,
  [SMALL_STATE(135)] = 3236,
  [SMALL_STATE(136)] = 3248,
  [SMALL_STATE(137)] = 3259,
  [SMALL_STATE(138)] = 3272,
  [SMALL_STATE(139)] = 3281,
  [SMALL_STATE(140)] = 3294,
  [SMALL_STATE(141)] = 3305,
  [SMALL_STATE(142)] = 3318,
  [SMALL_STATE(143)] = 3331,
  [SMALL_STATE(144)] = 3342,
  [SMALL_STATE(145)] = 3355,
  [SMALL_STATE(146)] = 3366,
  [SMALL_STATE(147)] = 3376,
  [SMALL_STATE(148)] = 3386,
  [SMALL_STATE(149)] = 3396,
  [SMALL_STATE(150)] = 3406,
  [SMALL_STATE(151)] = 3416,
  [SMALL_STATE(152)] = 3426,
  [SMALL_STATE(153)] = 3436,
  [SMALL_STATE(154)] = 3446,
  [SMALL_STATE(155)] = 3456,
  [SMALL_STATE(156)] = 3466,
  [SMALL_STATE(157)] = 3476,
  [SMALL_STATE(158)] = 3484,
  [SMALL_STATE(159)] = 3494,
  [SMALL_STATE(160)] = 3504,
  [SMALL_STATE(161)] = 3514,
  [SMALL_STATE(162)] = 3524,
  [SMALL_STATE(163)] = 3534,
  [SMALL_STATE(164)] = 3544,
  [SMALL_STATE(165)] = 3554,
  [SMALL_STATE(166)] = 3564,
  [SMALL_STATE(167)] = 3574,
  [SMALL_STATE(168)] = 3581,
  [SMALL_STATE(169)] = 3588,
  [SMALL_STATE(170)] = 3595,
  [SMALL_STATE(171)] = 3602,
  [SMALL_STATE(172)] = 3609,
  [SMALL_STATE(173)] = 3616,
  [SMALL_STATE(174)] = 3623,
  [SMALL_STATE(175)] = 3630,
  [SMALL_STATE(176)] = 3637,
  [SMALL_STATE(177)] = 3644,
  [SMALL_STATE(178)] = 3651,
  [SMALL_STATE(179)] = 3658,
  [SMALL_STATE(180)] = 3665,
  [SMALL_STATE(181)] = 3672,
  [SMALL_STATE(182)] = 3679,
  [SMALL_STATE(183)] = 3686,
  [SMALL_STATE(184)] = 3693,
  [SMALL_STATE(185)] = 3700,
  [SMALL_STATE(186)] = 3707,
  [SMALL_STATE(187)] = 3714,
  [SMALL_STATE(188)] = 3721,
  [SMALL_STATE(189)] = 3728,
  [SMALL_STATE(190)] = 3735,
  [SMALL_STATE(191)] = 3742,
  [SMALL_STATE(192)] = 3749,
  [SMALL_STATE(193)] = 3756,
  [SMALL_STATE(194)] = 3763,
  [SMALL_STATE(195)] = 3770,
  [SMALL_STATE(196)] = 3777,
  [SMALL_STATE(197)] = 3784,
  [SMALL_STATE(198)] = 3791,
  [SMALL_STATE(199)] = 3798,
  [SMALL_STATE(200)] = 3805,
  [SMALL_STATE(201)] = 3812,
  [SMALL_STATE(202)] = 3819,
  [SMALL_STATE(203)] = 3826,
  [SMALL_STATE(204)] = 3833,
  [SMALL_STATE(205)] = 3840,
  [SMALL_STATE(206)] = 3847,
  [SMALL_STATE(207)] = 3854,
  [SMALL_STATE(208)] = 3861,
  [SMALL_STATE(209)] = 3868,
  [SMALL_STATE(210)] = 3875,
  [SMALL_STATE(211)] = 3882,
  [SMALL_STATE(212)] = 3889,
  [SMALL_STATE(213)] = 3896,
  [SMALL_STATE(214)] = 3903,
  [SMALL_STATE(215)] = 3910,
  [SMALL_STATE(216)] = 3917,
  [SMALL_STATE(217)] = 3924,
  [SMALL_STATE(218)] = 3931,
  [SMALL_STATE(219)] = 3938,
  [SMALL_STATE(220)] = 3945,
  [SMALL_STATE(221)] = 3952,
  [SMALL_STATE(222)] = 3959,
  [SMALL_STATE(223)] = 3966,
  [SMALL_STATE(224)] = 3973,
  [SMALL_STATE(225)] = 3980,
  [SMALL_STATE(226)] = 3987,
  [SMALL_STATE(227)] = 3994,
  [SMALL_STATE(228)] = 4001,
  [SMALL_STATE(229)] = 4008,
  [SMALL_STATE(230)] = 4015,
  [SMALL_STATE(231)] = 4022,
  [SMALL_STATE(232)] = 4029,
  [SMALL_STATE(233)] = 4036,
  [SMALL_STATE(234)] = 4043,
  [SMALL_STATE(235)] = 4050,
  [SMALL_STATE(236)] = 4057,
  [SMALL_STATE(237)] = 4064,
  [SMALL_STATE(238)] = 4071,
  [SMALL_STATE(239)] = 4078,
  [SMALL_STATE(240)] = 4085,
  [SMALL_STATE(241)] = 4092,
  [SMALL_STATE(242)] = 4099,
  [SMALL_STATE(243)] = 4106,
  [SMALL_STATE(244)] = 4113,
  [SMALL_STATE(245)] = 4120,
  [SMALL_STATE(246)] = 4127,
  [SMALL_STATE(247)] = 4134,
  [SMALL_STATE(248)] = 4141,
  [SMALL_STATE(249)] = 4148,
  [SMALL_STATE(250)] = 4155,
  [SMALL_STATE(251)] = 4162,
  [SMALL_STATE(252)] = 4169,
  [SMALL_STATE(253)] = 4176,
  [SMALL_STATE(254)] = 4183,
  [SMALL_STATE(255)] = 4190,
  [SMALL_STATE(256)] = 4197,
  [SMALL_STATE(257)] = 4204,
  [SMALL_STATE(258)] = 4211,
  [SMALL_STATE(259)] = 4218,
  [SMALL_STATE(260)] = 4225,
  [SMALL_STATE(261)] = 4232,
  [SMALL_STATE(262)] = 4239,
  [SMALL_STATE(263)] = 4246,
  [SMALL_STATE(264)] = 4253,
  [SMALL_STATE(265)] = 4260,
  [SMALL_STATE(266)] = 4267,
  [SMALL_STATE(267)] = 4274,
  [SMALL_STATE(268)] = 4281,
  [SMALL_STATE(269)] = 4288,
  [SMALL_STATE(270)] = 4295,
  [SMALL_STATE(271)] = 4302,
  [SMALL_STATE(272)] = 4309,
  [SMALL_STATE(273)] = 4316,
  [SMALL_STATE(274)] = 4323,
  [SMALL_STATE(275)] = 4330,
  [SMALL_STATE(276)] = 4337,
  [SMALL_STATE(277)] = 4344,
  [SMALL_STATE(278)] = 4351,
  [SMALL_STATE(279)] = 4358,
  [SMALL_STATE(280)] = 4365,
  [SMALL_STATE(281)] = 4372,
  [SMALL_STATE(282)] = 4379,
  [SMALL_STATE(283)] = 4386,
  [SMALL_STATE(284)] = 4393,
  [SMALL_STATE(285)] = 4400,
  [SMALL_STATE(286)] = 4407,
  [SMALL_STATE(287)] = 4414,
  [SMALL_STATE(288)] = 4421,
  [SMALL_STATE(289)] = 4428,
  [SMALL_STATE(290)] = 4435,
  [SMALL_STATE(291)] = 4442,
  [SMALL_STATE(292)] = 4449,
  [SMALL_STATE(293)] = 4456,
  [SMALL_STATE(294)] = 4463,
  [SMALL_STATE(295)] = 4470,
  [SMALL_STATE(296)] = 4477,
  [SMALL_STATE(297)] = 4484,
  [SMALL_STATE(298)] = 4491,
  [SMALL_STATE(299)] = 4498,
  [SMALL_STATE(300)] = 4505,
  [SMALL_STATE(301)] = 4512,
  [SMALL_STATE(302)] = 4519,
  [SMALL_STATE(303)] = 4526,
  [SMALL_STATE(304)] = 4533,
  [SMALL_STATE(305)] = 4540,
  [SMALL_STATE(306)] = 4547,
  [SMALL_STATE(307)] = 4554,
  [SMALL_STATE(308)] = 4561,
  [SMALL_STATE(309)] = 4568,
  [SMALL_STATE(310)] = 4575,
  [SMALL_STATE(311)] = 4582,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(183),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(310),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(304),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(303),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(294),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(293),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(292),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(291),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(285),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [33] = {.entry = {.count = 1, .reusable = false}}, SHIFT(116),
  [35] = {.entry = {.count = 1, .reusable = false}}, SHIFT(122),
  [37] = {.entry = {.count = 1, .reusable = true}}, SHIFT(122),
  [39] = {.entry = {.count = 1, .reusable = true}}, SHIFT(65),
  [41] = {.entry = {.count = 1, .reusable = false}}, SHIFT(65),
  [43] = {.entry = {.count = 1, .reusable = true}}, SHIFT(280),
  [45] = {.entry = {.count = 1, .reusable = false}}, SHIFT(280),
  [47] = {.entry = {.count = 1, .reusable = true}}, SHIFT(279),
  [49] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [51] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3),
  [53] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(183),
  [56] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(5),
  [59] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(310),
  [62] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(304),
  [65] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(303),
  [68] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(294),
  [71] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(293),
  [74] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(292),
  [77] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(291),
  [80] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(285),
  [83] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(47),
  [86] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(63),
  [89] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(116),
  [92] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(116),
  [95] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(122),
  [98] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(122),
  [101] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(65),
  [104] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(65),
  [107] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(280),
  [110] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(280),
  [113] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(279),
  [116] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2, .production_id = 3), SHIFT_REPEAT(18),
  [119] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1, .production_id = 1),
  [121] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [123] = {.entry = {.count = 1, .reusable = true}}, SHIFT(212),
  [125] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [127] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 15),
  [129] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 15),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 6),
  [133] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 6),
  [135] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [137] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [139] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_field, 1),
  [141] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_field, 1),
  [143] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2, .production_id = 2),
  [145] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2, .production_id = 2),
  [147] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__expression, 1, .production_id = 1),
  [149] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__expression, 1, .production_id = 1),
  [151] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__bool_lhs, 1, .production_id = 1),
  [153] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__bool_lhs, 1, .production_id = 1),
  [155] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 6),
  [157] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 6),
  [159] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [161] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [163] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [165] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [167] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 7),
  [169] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 7),
  [171] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 7),
  [173] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 7),
  [175] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__boollike_field, 4, .production_id = 11),
  [177] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__boollike_field, 4, .production_id = 11),
  [179] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3, .production_id = 4),
  [181] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3, .production_id = 4),
  [183] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [185] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [187] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 5),
  [189] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [191] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [193] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [195] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [197] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 5),
  [199] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 6, .production_id = 20),
  [201] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 6, .production_id = 20),
  [203] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1, .production_id = 1),
  [205] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [207] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [209] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1, .production_id = 1),
  [211] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [213] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [215] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__stringlike_field, 4, .production_id = 11),
  [217] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__stringlike_field, 4, .production_id = 11),
  [219] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [221] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [223] = {.entry = {.count = 1, .reusable = true}}, SHIFT(219),
  [225] = {.entry = {.count = 1, .reusable = true}}, SHIFT(218),
  [227] = {.entry = {.count = 1, .reusable = true}}, SHIFT(217),
  [229] = {.entry = {.count = 1, .reusable = true}}, SHIFT(211),
  [231] = {.entry = {.count = 1, .reusable = true}}, SHIFT(210),
  [233] = {.entry = {.count = 1, .reusable = true}}, SHIFT(209),
  [235] = {.entry = {.count = 1, .reusable = true}}, SHIFT(208),
  [237] = {.entry = {.count = 1, .reusable = true}}, SHIFT(157),
  [239] = {.entry = {.count = 1, .reusable = true}}, SHIFT(160),
  [241] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(306),
  [244] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3),
  [246] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(298),
  [249] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(289),
  [252] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(311),
  [255] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(307),
  [258] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(299),
  [261] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(290),
  [264] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(84),
  [267] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(65),
  [270] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(65),
  [273] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(280),
  [276] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(280),
  [279] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 3), SHIFT_REPEAT(279),
  [282] = {.entry = {.count = 1, .reusable = true}}, SHIFT(306),
  [284] = {.entry = {.count = 1, .reusable = true}}, SHIFT(105),
  [286] = {.entry = {.count = 1, .reusable = true}}, SHIFT(298),
  [288] = {.entry = {.count = 1, .reusable = true}}, SHIFT(289),
  [290] = {.entry = {.count = 1, .reusable = true}}, SHIFT(311),
  [292] = {.entry = {.count = 1, .reusable = true}}, SHIFT(307),
  [294] = {.entry = {.count = 1, .reusable = true}}, SHIFT(299),
  [296] = {.entry = {.count = 1, .reusable = true}}, SHIFT(290),
  [298] = {.entry = {.count = 1, .reusable = true}}, SHIFT(84),
  [300] = {.entry = {.count = 1, .reusable = true}}, SHIFT(149),
  [302] = {.entry = {.count = 1, .reusable = true}}, SHIFT(113),
  [304] = {.entry = {.count = 1, .reusable = true}}, SHIFT(247),
  [306] = {.entry = {.count = 1, .reusable = true}}, SHIFT(207),
  [308] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [310] = {.entry = {.count = 1, .reusable = true}}, SHIFT(85),
  [312] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [314] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [316] = {.entry = {.count = 1, .reusable = true}}, SHIFT(86),
  [318] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [320] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [322] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [324] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [326] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [328] = {.entry = {.count = 1, .reusable = true}}, SHIFT(184),
  [330] = {.entry = {.count = 1, .reusable = true}}, SHIFT(172),
  [332] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [334] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [336] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 8, .production_id = 21),
  [338] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 8, .production_id = 21),
  [340] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 5, .production_id = 13),
  [342] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 5, .production_id = 13),
  [344] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [346] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [348] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 9),
  [350] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 9),
  [352] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 8),
  [354] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 8),
  [356] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 19),
  [358] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 19),
  [360] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 10),
  [362] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 10),
  [364] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 18),
  [366] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 18),
  [368] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 17),
  [370] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 17),
  [372] = {.entry = {.count = 1, .reusable = true}}, SHIFT(152),
  [374] = {.entry = {.count = 1, .reusable = true}}, SHIFT(253),
  [376] = {.entry = {.count = 1, .reusable = true}}, SHIFT(248),
  [378] = {.entry = {.count = 1, .reusable = true}}, SHIFT(246),
  [380] = {.entry = {.count = 1, .reusable = true}}, SHIFT(245),
  [382] = {.entry = {.count = 1, .reusable = true}}, SHIFT(244),
  [384] = {.entry = {.count = 1, .reusable = true}}, SHIFT(243),
  [386] = {.entry = {.count = 1, .reusable = true}}, SHIFT(242),
  [388] = {.entry = {.count = 1, .reusable = true}}, SHIFT(241),
  [390] = {.entry = {.count = 1, .reusable = false}}, SHIFT(240),
  [392] = {.entry = {.count = 1, .reusable = true}}, SHIFT(239),
  [394] = {.entry = {.count = 1, .reusable = false}}, SHIFT(238),
  [396] = {.entry = {.count = 1, .reusable = true}}, SHIFT(237),
  [398] = {.entry = {.count = 1, .reusable = true}}, SHIFT(236),
  [400] = {.entry = {.count = 1, .reusable = true}}, SHIFT(167),
  [402] = {.entry = {.count = 1, .reusable = true}}, SHIFT(226),
  [404] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__numberlike_field, 4, .production_id = 11),
  [406] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__numberlike_field, 4, .production_id = 11),
  [408] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [410] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [412] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__number_lhs, 1, .production_id = 1),
  [414] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__number_lhs, 1, .production_id = 1),
  [416] = {.entry = {.count = 1, .reusable = true}}, SHIFT(148),
  [418] = {.entry = {.count = 1, .reusable = true}}, SHIFT(269),
  [420] = {.entry = {.count = 1, .reusable = true}}, SHIFT(268),
  [422] = {.entry = {.count = 1, .reusable = true}}, SHIFT(267),
  [424] = {.entry = {.count = 1, .reusable = true}}, SHIFT(266),
  [426] = {.entry = {.count = 1, .reusable = true}}, SHIFT(265),
  [428] = {.entry = {.count = 1, .reusable = true}}, SHIFT(264),
  [430] = {.entry = {.count = 1, .reusable = true}}, SHIFT(263),
  [432] = {.entry = {.count = 1, .reusable = true}}, SHIFT(262),
  [434] = {.entry = {.count = 1, .reusable = false}}, SHIFT(261),
  [436] = {.entry = {.count = 1, .reusable = true}}, SHIFT(257),
  [438] = {.entry = {.count = 1, .reusable = false}}, SHIFT(256),
  [440] = {.entry = {.count = 1, .reusable = true}}, SHIFT(254),
  [442] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 8),
  [444] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 8),
  [446] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 9),
  [448] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 9),
  [450] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [452] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [454] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [456] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(12),
  [459] = {.entry = {.count = 1, .reusable = true}}, SHIFT(139),
  [461] = {.entry = {.count = 1, .reusable = true}}, SHIFT(140),
  [463] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [465] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [467] = {.entry = {.count = 1, .reusable = true}}, SHIFT(224),
  [469] = {.entry = {.count = 1, .reusable = true}}, SHIFT(135),
  [471] = {.entry = {.count = 1, .reusable = true}}, SHIFT(162),
  [473] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 2, .production_id = 1),
  [475] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2),
  [477] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2), SHIFT_REPEAT(135),
  [480] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 5, .production_id = 12),
  [482] = {.entry = {.count = 1, .reusable = true}}, SHIFT(104),
  [484] = {.entry = {.count = 1, .reusable = true}}, SHIFT(138),
  [486] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 1),
  [488] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [490] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(137),
  [493] = {.entry = {.count = 1, .reusable = true}}, SHIFT(129),
  [495] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [497] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [499] = {.entry = {.count = 1, .reusable = true}}, SHIFT(144),
  [501] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [503] = {.entry = {.count = 1, .reusable = true}}, SHIFT(137),
  [505] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [507] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(144),
  [510] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 5, .production_id = 14),
  [512] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 5, .production_id = 14),
  [514] = {.entry = {.count = 1, .reusable = true}}, SHIFT(165),
  [516] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 6, .production_id = 17),
  [518] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 6, .production_id = 17),
  [520] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 6, .production_id = 18),
  [522] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 6, .production_id = 18),
  [524] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__bool_array, 6, .production_id = 20),
  [526] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__bool_array, 6, .production_id = 20),
  [528] = {.entry = {.count = 1, .reusable = true}}, SHIFT(159),
  [530] = {.entry = {.count = 1, .reusable = true}}, SHIFT(277),
  [532] = {.entry = {.count = 1, .reusable = true}}, SHIFT(222),
  [534] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 8, .production_id = 21),
  [536] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 8, .production_id = 21),
  [538] = {.entry = {.count = 1, .reusable = true}}, SHIFT(195),
  [540] = {.entry = {.count = 1, .reusable = false}}, SHIFT(223),
  [542] = {.entry = {.count = 1, .reusable = true}}, SHIFT(194),
  [544] = {.entry = {.count = 1, .reusable = false}}, SHIFT(225),
  [546] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [548] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 4, .production_id = 8),
  [550] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 4, .production_id = 8),
  [552] = {.entry = {.count = 1, .reusable = true}}, SHIFT(141),
  [554] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_string_field, 1),
  [556] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_string_field, 1),
  [558] = {.entry = {.count = 1, .reusable = true}}, SHIFT(131),
  [560] = {.entry = {.count = 1, .reusable = false}}, SHIFT(221),
  [562] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 5, .production_id = 13),
  [564] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 5, .production_id = 13),
  [566] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 4, .production_id = 12),
  [568] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 4, .production_id = 12),
  [570] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__number_array, 4, .production_id = 8),
  [572] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__number_array, 4, .production_id = 8),
  [574] = {.entry = {.count = 1, .reusable = true}}, SHIFT(142),
  [576] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array, 4, .production_id = 10),
  [578] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_array, 4, .production_id = 10),
  [580] = {.entry = {.count = 1, .reusable = true}}, SHIFT(50),
  [582] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [584] = {.entry = {.count = 1, .reusable = true}}, SHIFT(213),
  [586] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [588] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [590] = {.entry = {.count = 1, .reusable = true}}, SHIFT(100),
  [592] = {.entry = {.count = 1, .reusable = true}}, SHIFT(205),
  [594] = {.entry = {.count = 1, .reusable = true}}, SHIFT(204),
  [596] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [598] = {.entry = {.count = 1, .reusable = true}}, SHIFT(119),
  [600] = {.entry = {.count = 1, .reusable = true}}, SHIFT(201),
  [602] = {.entry = {.count = 1, .reusable = true}}, SHIFT(111),
  [604] = {.entry = {.count = 1, .reusable = true}}, SHIFT(199),
  [606] = {.entry = {.count = 1, .reusable = true}}, SHIFT(106),
  [608] = {.entry = {.count = 1, .reusable = true}}, SHIFT(107),
  [610] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [612] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [614] = {.entry = {.count = 1, .reusable = true}}, SHIFT(89),
  [616] = {.entry = {.count = 1, .reusable = true}}, SHIFT(191),
  [618] = {.entry = {.count = 1, .reusable = true}}, SHIFT(227),
  [620] = {.entry = {.count = 1, .reusable = true}}, SHIFT(228),
  [622] = {.entry = {.count = 1, .reusable = true}}, SHIFT(229),
  [624] = {.entry = {.count = 1, .reusable = true}}, SHIFT(230),
  [626] = {.entry = {.count = 1, .reusable = true}}, SHIFT(231),
  [628] = {.entry = {.count = 1, .reusable = true}}, SHIFT(190),
  [630] = {.entry = {.count = 1, .reusable = true}}, SHIFT(189),
  [632] = {.entry = {.count = 1, .reusable = true}}, SHIFT(232),
  [634] = {.entry = {.count = 1, .reusable = true}}, SHIFT(233),
  [636] = {.entry = {.count = 1, .reusable = true}}, SHIFT(188),
  [638] = {.entry = {.count = 1, .reusable = true}}, SHIFT(187),
  [640] = {.entry = {.count = 1, .reusable = true}}, SHIFT(109),
  [642] = {.entry = {.count = 1, .reusable = true}}, SHIFT(185),
  [644] = {.entry = {.count = 1, .reusable = true}}, SHIFT(153),
  [646] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [648] = {.entry = {.count = 1, .reusable = true}}, SHIFT(234),
  [650] = {.entry = {.count = 1, .reusable = true}}, SHIFT(235),
  [652] = {.entry = {.count = 1, .reusable = true}}, SHIFT(74),
  [654] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [656] = {.entry = {.count = 1, .reusable = true}}, SHIFT(98),
  [658] = {.entry = {.count = 1, .reusable = true}}, SHIFT(125),
  [660] = {.entry = {.count = 1, .reusable = true}}, SHIFT(88),
  [662] = {.entry = {.count = 1, .reusable = true}}, SHIFT(97),
  [664] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [666] = {.entry = {.count = 1, .reusable = true}}, SHIFT(281),
  [668] = {.entry = {.count = 1, .reusable = true}}, SHIFT(282),
  [670] = {.entry = {.count = 1, .reusable = true}}, SHIFT(96),
  [672] = {.entry = {.count = 1, .reusable = true}}, SHIFT(93),
  [674] = {.entry = {.count = 1, .reusable = true}}, SHIFT(94),
  [676] = {.entry = {.count = 1, .reusable = true}}, SHIFT(169),
  [678] = {.entry = {.count = 1, .reusable = true}}, SHIFT(171),
  [680] = {.entry = {.count = 1, .reusable = true}}, SHIFT(249),
  [682] = {.entry = {.count = 1, .reusable = true}}, SHIFT(170),
  [684] = {.entry = {.count = 1, .reusable = true}}, SHIFT(168),
  [686] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [688] = {.entry = {.count = 1, .reusable = true}}, SHIFT(250),
  [690] = {.entry = {.count = 1, .reusable = true}}, SHIFT(251),
  [692] = {.entry = {.count = 1, .reusable = true}}, SHIFT(252),
  [694] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [696] = {.entry = {.count = 1, .reusable = true}}, SHIFT(110),
  [698] = {.entry = {.count = 1, .reusable = true}}, SHIFT(255),
  [700] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [702] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [704] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [706] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [708] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [710] = {.entry = {.count = 1, .reusable = true}}, SHIFT(45),
  [712] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [714] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [716] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [718] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [720] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [722] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [724] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [726] = {.entry = {.count = 1, .reusable = true}}, SHIFT(133),
  [728] = {.entry = {.count = 1, .reusable = true}}, SHIFT(258),
  [730] = {.entry = {.count = 1, .reusable = true}}, SHIFT(259),
  [732] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [734] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [736] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [738] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [740] = {.entry = {.count = 1, .reusable = true}}, SHIFT(260),
  [742] = {.entry = {.count = 1, .reusable = true}}, SHIFT(103),
  [744] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [746] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [748] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [750] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [752] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [754] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [756] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [758] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [760] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [762] = {.entry = {.count = 1, .reusable = true}}, SHIFT(220),
  [764] = {.entry = {.count = 1, .reusable = true}}, SHIFT(221),
  [766] = {.entry = {.count = 1, .reusable = true}}, SHIFT(223),
  [768] = {.entry = {.count = 1, .reusable = true}}, SHIFT(225),
  [770] = {.entry = {.count = 1, .reusable = true}}, SHIFT(158),
  [772] = {.entry = {.count = 1, .reusable = true}}, SHIFT(166),
  [774] = {.entry = {.count = 1, .reusable = true}}, SHIFT(164),
  [776] = {.entry = {.count = 1, .reusable = true}}, SHIFT(163),
  [778] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [780] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_map_string_array_field, 1),
  [782] = {.entry = {.count = 1, .reusable = true}}, SHIFT(147),
  [784] = {.entry = {.count = 1, .reusable = true}}, SHIFT(146),
  [786] = {.entry = {.count = 1, .reusable = true}}, SHIFT(82),
  [788] = {.entry = {.count = 1, .reusable = true}}, SHIFT(150),
  [790] = {.entry = {.count = 1, .reusable = true}}, SHIFT(151),
  [792] = {.entry = {.count = 1, .reusable = true}}, SHIFT(154),
  [794] = {.entry = {.count = 1, .reusable = true}}, SHIFT(99),
  [796] = {.entry = {.count = 1, .reusable = true}}, SHIFT(101),
  [798] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [800] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [802] = {.entry = {.count = 1, .reusable = true}}, SHIFT(87),
  [804] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [806] = {.entry = {.count = 1, .reusable = true}}, SHIFT(286),
  [808] = {.entry = {.count = 1, .reusable = true}}, SHIFT(287),
  [810] = {.entry = {.count = 1, .reusable = true}}, SHIFT(288),
  [812] = {.entry = {.count = 1, .reusable = true}}, SHIFT(95),
  [814] = {.entry = {.count = 1, .reusable = true}}, SHIFT(126),
  [816] = {.entry = {.count = 1, .reusable = true}}, SHIFT(77),
  [818] = {.entry = {.count = 1, .reusable = true}}, SHIFT(295),
  [820] = {.entry = {.count = 1, .reusable = true}}, SHIFT(296),
  [822] = {.entry = {.count = 1, .reusable = true}}, SHIFT(81),
  [824] = {.entry = {.count = 1, .reusable = true}}, SHIFT(80),
  [826] = {.entry = {.count = 1, .reusable = true}}, SHIFT(297),
  [828] = {.entry = {.count = 1, .reusable = true}}, SHIFT(92),
  [830] = {.entry = {.count = 1, .reusable = true}}, SHIFT(91),
  [832] = {.entry = {.count = 1, .reusable = true}}, SHIFT(305),
  [834] = {.entry = {.count = 1, .reusable = true}}, SHIFT(308),
  [836] = {.entry = {.count = 1, .reusable = true}}, SHIFT(79),
  [838] = {.entry = {.count = 1, .reusable = true}}, SHIFT(90),
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
