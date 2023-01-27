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
#define STATE_COUNT 245
#define LARGE_STATE_COUNT 44
#define SYMBOL_COUNT 144
#define ALIAS_COUNT 0
#define TOKEN_COUNT 108
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 16
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 23

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
  anon_sym_LBRACK = 51,
  anon_sym_RBRACK = 52,
  anon_sym_STAR = 53,
  anon_sym_LBRACK_STAR_RBRACK = 54,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTsec = 55,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec = 56,
  anon_sym_ip_DOTgeoip_DOTasnum = 57,
  anon_sym_cf_DOTbot_management_DOTscore = 58,
  anon_sym_cf_DOTedge_DOTserver_port = 59,
  anon_sym_cf_DOTthreat_score = 60,
  anon_sym_cf_DOTwaf_DOTscore = 61,
  anon_sym_cf_DOTwaf_DOTscore_DOTsqli = 62,
  anon_sym_cf_DOTwaf_DOTscore_DOTxss = 63,
  anon_sym_cf_DOTwaf_DOTscore_DOTrce = 64,
  anon_sym_ip_DOTsrc = 65,
  anon_sym_cf_DOTedge_DOTserver_ip = 66,
  anon_sym_http_DOTcookie = 67,
  anon_sym_http_DOThost = 68,
  anon_sym_http_DOTreferer = 69,
  anon_sym_http_DOTrequest_DOTfull_uri = 70,
  anon_sym_http_DOTrequest_DOTmethod = 71,
  anon_sym_http_DOTrequest_DOTuri = 72,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 73,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 74,
  anon_sym_http_DOTuser_agent = 75,
  anon_sym_http_DOTrequest_DOTversion = 76,
  anon_sym_http_DOTx_forwarded_for = 77,
  anon_sym_ip_DOTsrc_DOTlat = 78,
  anon_sym_ip_DOTsrc_DOTlon = 79,
  anon_sym_ip_DOTsrc_DOTcity = 80,
  anon_sym_ip_DOTsrc_DOTpostal_code = 81,
  anon_sym_ip_DOTsrc_DOTmetro_code = 82,
  anon_sym_ip_DOTgeoip_DOTcontinent = 83,
  anon_sym_ip_DOTgeoip_DOTcountry = 84,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 85,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 86,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 87,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 88,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 89,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 90,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 91,
  anon_sym_cf_DOThostname_DOTmetadata = 92,
  anon_sym_cf_DOTworker_DOTupstream_zone = 93,
  anon_sym_cf_DOTrandom_seed = 94,
  anon_sym_http_DOTrequest_DOTcookies = 95,
  anon_sym_http_DOTrequest_DOTheaders = 96,
  anon_sym_http_DOTrequest_DOTheaders_DOTnames = 97,
  anon_sym_http_DOTrequest_DOTheaders_DOTvalues = 98,
  anon_sym_http_DOTrequest_DOTaccepted_languages = 99,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 100,
  anon_sym_ssl = 101,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 102,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 103,
  anon_sym_cf_DOTclient_DOTbot = 104,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 105,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 106,
  anon_sym_http_DOTrequest_DOTheaders_DOTtruncated = 107,
  sym_source_file = 108,
  sym__expression = 109,
  sym_not_expression = 110,
  sym_in_expression = 111,
  sym_compound_expression = 112,
  sym_ip_set = 113,
  sym_string_set = 114,
  sym_number_set = 115,
  sym_simple_expression = 116,
  sym__bool_lhs = 117,
  sym__number_lhs = 118,
  sym__string_lhs = 119,
  sym_string_func = 120,
  sym_number_func = 121,
  sym_bool_func = 122,
  sym_group = 123,
  sym_boolean = 124,
  sym__ip = 125,
  sym_ip_range = 126,
  sym_not_operator = 127,
  sym__array_lhs = 128,
  sym_array_field_expansion = 129,
  sym__stringlike_field = 130,
  sym_number_field = 131,
  sym_ip_field = 132,
  sym_string_field = 133,
  sym_bytes_field = 134,
  sym_map_string_array_field = 135,
  sym_array_string_field = 136,
  sym_bool_field = 137,
  aux_sym_source_file_repeat1 = 138,
  aux_sym_ip_set_repeat1 = 139,
  aux_sym_string_set_repeat1 = 140,
  aux_sym_number_set_repeat1 = 141,
  aux_sym_string_func_repeat1 = 142,
  aux_sym_string_func_repeat2 = 143,
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
  [anon_sym_LBRACK_STAR_RBRACK] = "[*]",
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
  [sym__array_lhs] = "_array_lhs",
  [sym_array_field_expansion] = "array_field_expansion",
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
  [anon_sym_LBRACK_STAR_RBRACK] = anon_sym_LBRACK_STAR_RBRACK,
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
  [sym__array_lhs] = sym__array_lhs,
  [sym_array_field_expansion] = sym_array_field_expansion,
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
  [anon_sym_LBRACK_STAR_RBRACK] = {
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
  [sym__array_lhs] = {
    .visible = false,
    .named = true,
  },
  [sym_array_field_expansion] = {
    .visible = true,
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
  [2] = {.index = 10, .length = 1},
  [3] = {.index = 11, .length = 3},
  [4] = {.index = 14, .length = 13},
  [5] = {.index = 27, .length = 2},
  [6] = {.index = 29, .length = 12},
  [7] = {.index = 41, .length = 2},
  [8] = {.index = 43, .length = 12},
  [9] = {.index = 55, .length = 11},
  [10] = {.index = 66, .length = 1},
  [11] = {.index = 67, .length = 3},
  [12] = {.index = 70, .length = 13},
  [13] = {.index = 83, .length = 2},
  [14] = {.index = 85, .length = 11},
  [15] = {.index = 96, .length = 20},
  [16] = {.index = 116, .length = 21},
  [17] = {.index = 137, .length = 3},
  [18] = {.index = 140, .length = 13},
  [19] = {.index = 153, .length = 3},
  [20] = {.index = 156, .length = 13},
  [21] = {.index = 169, .length = 4},
  [22] = {.index = 173, .length = 14},
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
    {field_inner, 1},
  [11] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [14] =
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
  [27] =
    {field_field, 2},
    {field_func, 0},
  [29] =
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
  [41] =
    {field_func, 0},
    {field_seed, 2},
  [43] =
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
  [55] =
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
  [66] =
    {field_key, 2},
  [67] =
    {field_field, 2},
    {field_func, 0},
    {field_keys, 3},
  [70] =
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
  [83] =
    {field_ip, 0},
    {field_mask, 2},
  [85] =
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
  [96] =
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
  [116] =
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
  [137] =
    {field_field, 2},
    {field_func, 0},
    {field_replacement, 4},
  [140] =
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
  [153] =
    {field_field, 2},
    {field_func, 0},
    {field_value, 4},
  [156] =
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
  [169] =
    {field_func, 0},
    {field_regex, 4},
    {field_replacement, 6},
    {field_source, 2},
  [173] =
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
  [49] = 47,
  [50] = 50,
  [51] = 51,
  [52] = 52,
  [53] = 53,
  [54] = 52,
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
  [70] = 68,
  [71] = 71,
  [72] = 69,
  [73] = 67,
  [74] = 74,
  [75] = 75,
  [76] = 75,
  [77] = 66,
  [78] = 71,
  [79] = 74,
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
  [105] = 101,
  [106] = 106,
  [107] = 107,
  [108] = 108,
  [109] = 109,
  [110] = 110,
  [111] = 109,
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
  [126] = 126,
  [127] = 127,
  [128] = 128,
  [129] = 129,
  [130] = 130,
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
  [143] = 143,
  [144] = 126,
  [145] = 145,
  [146] = 146,
  [147] = 147,
  [148] = 148,
  [149] = 149,
  [150] = 150,
  [151] = 151,
  [152] = 125,
  [153] = 153,
  [154] = 154,
  [155] = 155,
  [156] = 156,
  [157] = 157,
  [158] = 158,
  [159] = 124,
  [160] = 160,
  [161] = 161,
  [162] = 162,
  [163] = 163,
  [164] = 164,
  [165] = 165,
  [166] = 166,
  [167] = 123,
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
  [185] = 185,
  [186] = 134,
  [187] = 187,
  [188] = 122,
  [189] = 189,
  [190] = 190,
  [191] = 191,
  [192] = 192,
  [193] = 118,
  [194] = 194,
  [195] = 195,
  [196] = 121,
  [197] = 197,
  [198] = 198,
  [199] = 199,
  [200] = 200,
  [201] = 120,
  [202] = 127,
  [203] = 203,
  [204] = 204,
  [205] = 205,
  [206] = 206,
  [207] = 207,
  [208] = 208,
  [209] = 209,
  [210] = 210,
  [211] = 211,
  [212] = 166,
  [213] = 210,
  [214] = 214,
  [215] = 215,
  [216] = 216,
  [217] = 217,
  [218] = 218,
  [219] = 172,
  [220] = 175,
  [221] = 199,
  [222] = 142,
  [223] = 139,
  [224] = 224,
  [225] = 225,
  [226] = 226,
  [227] = 148,
  [228] = 154,
  [229] = 191,
  [230] = 143,
  [231] = 136,
  [232] = 178,
  [233] = 205,
  [234] = 234,
  [235] = 235,
  [236] = 236,
  [237] = 170,
  [238] = 145,
  [239] = 140,
  [240] = 138,
  [241] = 146,
  [242] = 217,
  [243] = 243,
  [244] = 141,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(704);
      if (lookahead == '!') ADVANCE(767);
      if (lookahead == '"') ADVANCE(3);
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == '$') ADVANCE(762);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(732);
      if (lookahead == ')') ADVANCE(734);
      if (lookahead == '*') ADVANCE(771);
      if (lookahead == ',') ADVANCE(733);
      if (lookahead == '/') ADVANCE(756);
      if (lookahead == '3') ADVANCE(746);
      if (lookahead == '<') ADVANCE(724);
      if (lookahead == '=') ADVANCE(51);
      if (lookahead == '>') ADVANCE(726);
      if (lookahead == '[') ADVANCE(769);
      if (lookahead == ']') ADVANCE(770);
      if (lookahead == '^') ADVANCE(53);
      if (lookahead == 'a') ADVANCE(397);
      if (lookahead == 'c') ADVANCE(291);
      if (lookahead == 'e') ADVANCE(409);
      if (lookahead == 'f') ADVANCE(91);
      if (lookahead == 'g') ADVANCE(197);
      if (lookahead == 'h') ADVANCE(617);
      if (lookahead == 'i') ADVANCE(399);
      if (lookahead == 'l') ADVANCE(198);
      if (lookahead == 'm') ADVANCE(98);
      if (lookahead == 'n') ADVANCE(200);
      if (lookahead == 'o') ADVANCE(516);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == 's') ADVANCE(574);
      if (lookahead == 't') ADVANCE(444);
      if (lookahead == 'u') ADVANCE(492);
      if (lookahead == 'x') ADVANCE(448);
      if (lookahead == '{') ADVANCE(712);
      if (lookahead == '|') ADVANCE(702);
      if (lookahead == '}') ADVANCE(713);
      if (lookahead == '~') ADVANCE(730);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(747);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(747);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(50);
      if (lookahead == '"') ADVANCE(3);
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == ')') ADVANCE(734);
      if (lookahead == ',') ADVANCE(733);
      if (lookahead == '<') ADVANCE(724);
      if (lookahead == '=') ADVANCE(51);
      if (lookahead == '>') ADVANCE(726);
      if (lookahead == 'c') ADVANCE(294);
      if (lookahead == 'e') ADVANCE(409);
      if (lookahead == 'g') ADVANCE(197);
      if (lookahead == 'h') ADVANCE(660);
      if (lookahead == 'i') ADVANCE(400);
      if (lookahead == 'l') ADVANCE(198);
      if (lookahead == 'm') ADVANCE(98);
      if (lookahead == 'n') ADVANCE(199);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == 's') ADVANCE(619);
      if (lookahead == 't') ADVANCE(443);
      if (lookahead == 'u') ADVANCE(492);
      if (lookahead == '}') ADVANCE(713);
      if (lookahead == '~') ADVANCE(730);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(747);
      END_STATE();
    case 2:
      if (lookahead == '!') ADVANCE(50);
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == ')') ADVANCE(734);
      if (lookahead == '3') ADVANCE(758);
      if (lookahead == '<') ADVANCE(724);
      if (lookahead == '=') ADVANCE(51);
      if (lookahead == '>') ADVANCE(726);
      if (lookahead == 'c') ADVANCE(483);
      if (lookahead == 'e') ADVANCE(513);
      if (lookahead == 'g') ADVANCE(197);
      if (lookahead == 'i') ADVANCE(398);
      if (lookahead == 'l') ADVANCE(219);
      if (lookahead == 'm') ADVANCE(98);
      if (lookahead == 'n') ADVANCE(199);
      if (lookahead == '~') ADVANCE(730);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(759);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(2)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(757);
      END_STATE();
    case 3:
      if (lookahead == '"') ADVANCE(748);
      if (lookahead != 0) ADVANCE(3);
      END_STATE();
    case 4:
      if (lookahead == '&') ADVANCE(706);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(137);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(305);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(147);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(159);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(109);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(125);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(301);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(360);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(391);
      END_STATE();
    case 14:
      if (lookahead == '.') ADVANCE(47);
      END_STATE();
    case 15:
      if (lookahead == '.') ADVANCE(47);
      if (lookahead == '5') ADVANCE(16);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(14);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(18);
      END_STATE();
    case 16:
      if (lookahead == '.') ADVANCE(47);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(14);
      END_STATE();
    case 17:
      if (lookahead == '.') ADVANCE(47);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(18);
      END_STATE();
    case 18:
      if (lookahead == '.') ADVANCE(47);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(14);
      END_STATE();
    case 19:
      if (lookahead == '.') ADVANCE(141);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(151);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(126);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(323);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(362);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(139);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(45);
      END_STATE();
    case 26:
      if (lookahead == '.') ADVANCE(45);
      if (lookahead == '5') ADVANCE(27);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(25);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(29);
      END_STATE();
    case 27:
      if (lookahead == '.') ADVANCE(45);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(25);
      END_STATE();
    case 28:
      if (lookahead == '.') ADVANCE(45);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(29);
      END_STATE();
    case 29:
      if (lookahead == '.') ADVANCE(45);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(25);
      END_STATE();
    case 30:
      if (lookahead == '.') ADVANCE(578);
      END_STATE();
    case 31:
      if (lookahead == '.') ADVANCE(163);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(507);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(311);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(46);
      END_STATE();
    case 35:
      if (lookahead == '.') ADVANCE(46);
      if (lookahead == '5') ADVANCE(36);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(34);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(38);
      END_STATE();
    case 36:
      if (lookahead == '.') ADVANCE(46);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(34);
      END_STATE();
    case 37:
      if (lookahead == '.') ADVANCE(46);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(38);
      END_STATE();
    case 38:
      if (lookahead == '.') ADVANCE(46);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(34);
      END_STATE();
    case 39:
      if (lookahead == '.') ADVANCE(666);
      END_STATE();
    case 40:
      if (lookahead == '.') ADVANCE(388);
      END_STATE();
    case 41:
      if (lookahead == '.') ADVANCE(548);
      END_STATE();
    case 42:
      if (lookahead == '.') ADVANCE(601);
      END_STATE();
    case 43:
      if (lookahead == '.') ADVANCE(148);
      END_STATE();
    case 44:
      if (lookahead == '1') ADVANCE(70);
      if (lookahead == '2') ADVANCE(90);
      END_STATE();
    case 45:
      if (lookahead == '2') ADVANCE(752);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(755);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(754);
      END_STATE();
    case 46:
      if (lookahead == '2') ADVANCE(26);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(28);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(29);
      END_STATE();
    case 47:
      if (lookahead == '2') ADVANCE(35);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(37);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(38);
      END_STATE();
    case 48:
      if (lookahead == '3') ADVANCE(67);
      END_STATE();
    case 49:
      if (lookahead == '4') ADVANCE(742);
      END_STATE();
    case 50:
      if (lookahead == '=') ADVANCE(723);
      END_STATE();
    case 51:
      if (lookahead == '=') ADVANCE(722);
      END_STATE();
    case 52:
      if (lookahead == ']') ADVANCE(772);
      END_STATE();
    case 53:
      if (lookahead == '^') ADVANCE(709);
      END_STATE();
    case 54:
      if (lookahead == '_') ADVANCE(384);
      END_STATE();
    case 55:
      if (lookahead == '_') ADVANCE(361);
      END_STATE();
    case 56:
      if (lookahead == '_') ADVANCE(136);
      END_STATE();
    case 57:
      if (lookahead == '_') ADVANCE(334);
      END_STATE();
    case 58:
      if (lookahead == '_') ADVANCE(44);
      END_STATE();
    case 59:
      if (lookahead == '_') ADVANCE(556);
      END_STATE();
    case 60:
      if (lookahead == '_') ADVANCE(688);
      END_STATE();
    case 61:
      if (lookahead == '_') ADVANCE(295);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(700);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(579);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(164);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(183);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(502);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(322);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(103);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(377);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(350);
      END_STATE();
    case 71:
      if (lookahead == '_') ADVANCE(228);
      END_STATE();
    case 72:
      if (lookahead == '_') ADVANCE(592);
      END_STATE();
    case 73:
      if (lookahead == '_') ADVANCE(539);
      END_STATE();
    case 74:
      if (lookahead == '_') ADVANCE(672);
      END_STATE();
    case 75:
      if (lookahead == '_') ADVANCE(670);
      END_STATE();
    case 76:
      if (lookahead == '_') ADVANCE(349);
      END_STATE();
    case 77:
      if (lookahead == '_') ADVANCE(674);
      END_STATE();
    case 78:
      if (lookahead == '_') ADVANCE(190);
      END_STATE();
    case 79:
      if (lookahead == '_') ADVANCE(691);
      END_STATE();
    case 80:
      if (lookahead == '_') ADVANCE(296);
      END_STATE();
    case 81:
      if (lookahead == '_') ADVANCE(140);
      END_STATE();
    case 82:
      if (lookahead == '_') ADVANCE(127);
      END_STATE();
    case 83:
      if (lookahead == '_') ADVANCE(165);
      END_STATE();
    case 84:
      if (lookahead == '_') ADVANCE(603);
      END_STATE();
    case 85:
      if (lookahead == '_') ADVANCE(167);
      END_STATE();
    case 86:
      if (lookahead == '_') ADVANCE(169);
      END_STATE();
    case 87:
      if (lookahead == '_') ADVANCE(170);
      END_STATE();
    case 88:
      if (lookahead == '_') ADVANCE(604);
      END_STATE();
    case 89:
      if (lookahead == '_') ADVANCE(396);
      END_STATE();
    case 90:
      if (lookahead == '_') ADVANCE(359);
      END_STATE();
    case 91:
      if (lookahead == 'a') ADVANCE(371);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(687);
      if (lookahead == 'e') ADVANCE(304);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(293);
      if (lookahead == 'o') ADVANCE(523);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(48);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(48);
      if (lookahead == 's') ADVANCE(78);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(810);
      END_STATE();
    case 97:
      if (lookahead == 'a') ADVANCE(414);
      if (lookahead == 'b') ADVANCE(458);
      if (lookahead == 'm') ADVANCE(102);
      if (lookahead == 'o') ADVANCE(501);
      if (lookahead == 'v') ADVANCE(495);
      END_STATE();
    case 98:
      if (lookahead == 'a') ADVANCE(607);
      END_STATE();
    case 99:
      if (lookahead == 'a') ADVANCE(527);
      END_STATE();
    case 100:
      if (lookahead == 'a') ADVANCE(333);
      END_STATE();
    case 101:
      if (lookahead == 'a') ADVANCE(387);
      END_STATE();
    case 102:
      if (lookahead == 'a') ADVANCE(372);
      END_STATE();
    case 103:
      if (lookahead == 'a') ADVANCE(673);
      END_STATE();
    case 104:
      if (lookahead == 'a') ADVANCE(386);
      END_STATE();
    case 105:
      if (lookahead == 'a') ADVANCE(382);
      END_STATE();
    case 106:
      if (lookahead == 'a') ADVANCE(392);
      END_STATE();
    case 107:
      if (lookahead == 'a') ADVANCE(609);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(153);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(589);
      if (lookahead == 'c') ADVANCE(447);
      if (lookahead == 'i') ADVANCE(584);
      if (lookahead == 's') ADVANCE(663);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(193);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(194);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(378);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(418);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(651);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(611);
      if (lookahead == 'o') ADVANCE(405);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(559);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(582);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(413);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(600);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(637);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(629);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(632);
      END_STATE();
    case 123:
      if (lookahead == 'a') ADVANCE(415);
      END_STATE();
    case 124:
      if (lookahead == 'a') ADVANCE(308);
      END_STATE();
    case 125:
      if (lookahead == 'a') ADVANCE(161);
      if (lookahead == 'c') ADVANCE(488);
      if (lookahead == 'f') ADVANCE(667);
      if (lookahead == 'h') ADVANCE(240);
      if (lookahead == 'm') ADVANCE(263);
      if (lookahead == 't') ADVANCE(355);
      if (lookahead == 'u') ADVANCE(531);
      if (lookahead == 'v') ADVANCE(259);
      END_STATE();
    case 126:
      if (lookahead == 'a') ADVANCE(161);
      if (lookahead == 'c') ADVANCE(488);
      if (lookahead == 'f') ADVANCE(667);
      if (lookahead == 'h') ADVANCE(286);
      if (lookahead == 'm') ADVANCE(263);
      if (lookahead == 'u') ADVANCE(531);
      if (lookahead == 'v') ADVANCE(259);
      END_STATE();
    case 127:
      if (lookahead == 'a') ADVANCE(310);
      END_STATE();
    case 128:
      if (lookahead == 'a') ADVANCE(547);
      END_STATE();
    case 129:
      if (lookahead == 'a') ADVANCE(309);
      END_STATE();
    case 130:
      if (lookahead == 'a') ADVANCE(428);
      END_STATE();
    case 131:
      if (lookahead == 'a') ADVANCE(649);
      END_STATE();
    case 132:
      if (lookahead == 'a') ADVANCE(389);
      END_STATE();
    case 133:
      if (lookahead == 'a') ADVANCE(195);
      END_STATE();
    case 134:
      if (lookahead == 'a') ADVANCE(312);
      END_STATE();
    case 135:
      if (lookahead == 'a') ADVANCE(441);
      END_STATE();
    case 136:
      if (lookahead == 'b') ADVANCE(699);
      END_STATE();
    case 137:
      if (lookahead == 'b') ADVANCE(456);
      if (lookahead == 'c') ADVANCE(370);
      if (lookahead == 'e') ADVANCE(173);
      if (lookahead == 'h') ADVANCE(471);
      if (lookahead == 'r') ADVANCE(123);
      if (lookahead == 't') ADVANCE(319);
      if (lookahead == 'w') ADVANCE(93);
      END_STATE();
    case 138:
      if (lookahead == 'b') ADVANCE(181);
      END_STATE();
    case 139:
      if (lookahead == 'b') ADVANCE(466);
      END_STATE();
    case 140:
      if (lookahead == 'b') ADVANCE(469);
      END_STATE();
    case 141:
      if (lookahead == 'b') ADVANCE(491);
      if (lookahead == 'h') ADVANCE(471);
      if (lookahead == 'w') ADVANCE(457);
      END_STATE();
    case 142:
      if (lookahead == 'c') ADVANCE(318);
      END_STATE();
    case 143:
      if (lookahead == 'c') ADVANCE(783);
      END_STATE();
    case 144:
      if (lookahead == 'c') ADVANCE(760);
      END_STATE();
    case 145:
      if (lookahead == 'c') ADVANCE(773);
      END_STATE();
    case 146:
      if (lookahead == 'c') ADVANCE(774);
      END_STATE();
    case 147:
      if (lookahead == 'c') ADVANCE(459);
      if (lookahead == 'h') ADVANCE(474);
      if (lookahead == 'r') ADVANCE(205);
      if (lookahead == 'u') ADVANCE(599);
      if (lookahead == 'x') ADVANCE(61);
      END_STATE();
    case 148:
      if (lookahead == 'c') ADVANCE(459);
      if (lookahead == 'h') ADVANCE(474);
      if (lookahead == 'r') ADVANCE(289);
      if (lookahead == 'u') ADVANCE(599);
      if (lookahead == 'x') ADVANCE(61);
      END_STATE();
    case 149:
      if (lookahead == 'c') ADVANCE(144);
      END_STATE();
    case 150:
      if (lookahead == 'c') ADVANCE(472);
      END_STATE();
    case 151:
      if (lookahead == 'c') ADVANCE(447);
      if (lookahead == 's') ADVANCE(663);
      END_STATE();
    case 152:
      if (lookahead == 'c') ADVANCE(8);
      END_STATE();
    case 153:
      if (lookahead == 'c') ADVANCE(210);
      END_STATE();
    case 154:
      if (lookahead == 'c') ADVANCE(212);
      END_STATE();
    case 155:
      if (lookahead == 'c') ADVANCE(657);
      END_STATE();
    case 156:
      if (lookahead == 'c') ADVANCE(234);
      END_STATE();
    case 157:
      if (lookahead == 'c') ADVANCE(107);
      END_STATE();
    case 158:
      if (lookahead == 'c') ADVANCE(107);
      if (lookahead == 't') ADVANCE(100);
      END_STATE();
    case 159:
      if (lookahead == 'c') ADVANCE(339);
      if (lookahead == 'l') ADVANCE(115);
      if (lookahead == 'm') ADVANCE(270);
      if (lookahead == 'p') ADVANCE(477);
      END_STATE();
    case 160:
      if (lookahead == 'c') ADVANCE(480);
      END_STATE();
    case 161:
      if (lookahead == 'c') ADVANCE(156);
      END_STATE();
    case 162:
      if (lookahead == 'c') ADVANCE(131);
      END_STATE();
    case 163:
      if (lookahead == 'c') ADVANCE(275);
      END_STATE();
    case 164:
      if (lookahead == 'c') ADVANCE(379);
      END_STATE();
    case 165:
      if (lookahead == 'c') ADVANCE(478);
      END_STATE();
    case 166:
      if (lookahead == 'c') ADVANCE(481);
      END_STATE();
    case 167:
      if (lookahead == 'c') ADVANCE(479);
      END_STATE();
    case 168:
      if (lookahead == 'c') ADVANCE(485);
      END_STATE();
    case 169:
      if (lookahead == 'c') ADVANCE(482);
      END_STATE();
    case 170:
      if (lookahead == 'c') ADVANCE(484);
      END_STATE();
    case 171:
      if (lookahead == 'd') ADVANCE(707);
      END_STATE();
    case 172:
      if (lookahead == 'd') ADVANCE(576);
      END_STATE();
    case 173:
      if (lookahead == 'd') ADVANCE(307);
      END_STATE();
    case 174:
      if (lookahead == 'd') ADVANCE(812);
      END_STATE();
    case 175:
      if (lookahead == 'd') ADVANCE(789);
      END_STATE();
    case 176:
      if (lookahead == 'd') ADVANCE(826);
      END_STATE();
    case 177:
      if (lookahead == 'd') ADVANCE(824);
      END_STATE();
    case 178:
      if (lookahead == 'd') ADVANCE(825);
      END_STATE();
    case 179:
      if (lookahead == 'd') ADVANCE(822);
      END_STATE();
    case 180:
      if (lookahead == 'd') ADVANCE(682);
      END_STATE();
    case 181:
      if (lookahead == 'd') ADVANCE(332);
      END_STATE();
    case 182:
      if (lookahead == 'd') ADVANCE(450);
      END_STATE();
    case 183:
      if (lookahead == 'd') ADVANCE(220);
      END_STATE();
    case 184:
      if (lookahead == 'd') ADVANCE(206);
      END_STATE();
    case 185:
      if (lookahead == 'd') ADVANCE(69);
      END_STATE();
    case 186:
      if (lookahead == 'd') ADVANCE(81);
      END_STATE();
    case 187:
      if (lookahead == 'd') ADVANCE(232);
      END_STATE();
    case 188:
      if (lookahead == 'd') ADVANCE(213);
      END_STATE();
    case 189:
      if (lookahead == 'd') ADVANCE(214);
      END_STATE();
    case 190:
      if (lookahead == 'd') ADVANCE(278);
      END_STATE();
    case 191:
      if (lookahead == 'd') ADVANCE(217);
      END_STATE();
    case 192:
      if (lookahead == 'd') ADVANCE(218);
      END_STATE();
    case 193:
      if (lookahead == 'd') ADVANCE(120);
      END_STATE();
    case 194:
      if (lookahead == 'd') ADVANCE(261);
      END_STATE();
    case 195:
      if (lookahead == 'd') ADVANCE(268);
      END_STATE();
    case 196:
      if (lookahead == 'd') ADVANCE(80);
      END_STATE();
    case 197:
      if (lookahead == 'e') ADVANCE(721);
      if (lookahead == 't') ADVANCE(720);
      END_STATE();
    case 198:
      if (lookahead == 'e') ADVANCE(719);
      if (lookahead == 'o') ADVANCE(445);
      if (lookahead == 't') ADVANCE(717);
      END_STATE();
    case 199:
      if (lookahead == 'e') ADVANCE(716);
      END_STATE();
    case 200:
      if (lookahead == 'e') ADVANCE(716);
      if (lookahead == 'o') ADVANCE(608);
      END_STATE();
    case 201:
      if (lookahead == 'e') ADVANCE(692);
      END_STATE();
    case 202:
      if (lookahead == 'e') ADVANCE(749);
      END_STATE();
    case 203:
      if (lookahead == 'e') ADVANCE(750);
      END_STATE();
    case 204:
      if (lookahead == 'e') ADVANCE(760);
      END_STATE();
    case 205:
      if (lookahead == 'e') ADVANCE(297);
      END_STATE();
    case 206:
      if (lookahead == 'e') ADVANCE(741);
      END_STATE();
    case 207:
      if (lookahead == 'e') ADVANCE(785);
      END_STATE();
    case 208:
      if (lookahead == 'e') ADVANCE(515);
      END_STATE();
    case 209:
      if (lookahead == 'e') ADVANCE(779);
      END_STATE();
    case 210:
      if (lookahead == 'e') ADVANCE(737);
      END_STATE();
    case 211:
      if (lookahead == 'e') ADVANCE(778);
      END_STATE();
    case 212:
      if (lookahead == 'e') ADVANCE(782);
      END_STATE();
    case 213:
      if (lookahead == 'e') ADVANCE(800);
      END_STATE();
    case 214:
      if (lookahead == 'e') ADVANCE(799);
      END_STATE();
    case 215:
      if (lookahead == 'e') ADVANCE(776);
      END_STATE();
    case 216:
      if (lookahead == 'e') ADVANCE(811);
      END_STATE();
    case 217:
      if (lookahead == 'e') ADVANCE(803);
      END_STATE();
    case 218:
      if (lookahead == 'e') ADVANCE(804);
      END_STATE();
    case 219:
      if (lookahead == 'e') ADVANCE(718);
      if (lookahead == 't') ADVANCE(717);
      END_STATE();
    case 220:
      if (lookahead == 'e') ADVANCE(150);
      END_STATE();
    case 221:
      if (lookahead == 'e') ADVANCE(518);
      END_STATE();
    case 222:
      if (lookahead == 'e') ADVANCE(454);
      END_STATE();
    case 223:
      if (lookahead == 'e') ADVANCE(497);
      END_STATE();
    case 224:
      if (lookahead == 'e') ADVANCE(565);
      END_STATE();
    case 225:
      if (lookahead == 'e') ADVANCE(685);
      END_STATE();
    case 226:
      if (lookahead == 'e') ADVANCE(519);
      END_STATE();
    case 227:
      if (lookahead == 'e') ADVANCE(42);
      END_STATE();
    case 228:
      if (lookahead == 'e') ADVANCE(671);
      END_STATE();
    case 229:
      if (lookahead == 'e') ADVANCE(419);
      END_STATE();
    case 230:
      if (lookahead == 'e') ADVANCE(174);
      END_STATE();
    case 231:
      if (lookahead == 'e') ADVANCE(421);
      END_STATE();
    case 232:
      if (lookahead == 'e') ADVANCE(196);
      END_STATE();
    case 233:
      if (lookahead == 'e') ADVANCE(56);
      END_STATE();
    case 234:
      if (lookahead == 'e') ADVANCE(508);
      END_STATE();
    case 235:
      if (lookahead == 'e') ADVANCE(532);
      END_STATE();
    case 236:
      if (lookahead == 'e') ADVANCE(567);
      END_STATE();
    case 237:
      if (lookahead == 'e') ADVANCE(155);
      END_STATE();
    case 238:
      if (lookahead == 'e') ADVANCE(533);
      END_STATE();
    case 239:
      if (lookahead == 'e') ADVANCE(40);
      END_STATE();
    case 240:
      if (lookahead == 'e') ADVANCE(111);
      END_STATE();
    case 241:
      if (lookahead == 'e') ADVANCE(561);
      END_STATE();
    case 242:
      if (lookahead == 'e') ADVANCE(564);
      END_STATE();
    case 243:
      if (lookahead == 'e') ADVANCE(145);
      END_STATE();
    case 244:
      if (lookahead == 'e') ADVANCE(104);
      END_STATE();
    case 245:
      if (lookahead == 'e') ADVANCE(185);
      END_STATE();
    case 246:
      if (lookahead == 'e') ADVANCE(146);
      END_STATE();
    case 247:
      if (lookahead == 'e') ADVANCE(176);
      END_STATE();
    case 248:
      if (lookahead == 'e') ADVANCE(626);
      END_STATE();
    case 249:
      if (lookahead == 'e') ADVANCE(525);
      END_STATE();
    case 250:
      if (lookahead == 'e') ADVANCE(177);
      END_STATE();
    case 251:
      if (lookahead == 'e') ADVANCE(178);
      END_STATE();
    case 252:
      if (lookahead == 'e') ADVANCE(569);
      END_STATE();
    case 253:
      if (lookahead == 'e') ADVANCE(521);
      END_STATE();
    case 254:
      if (lookahead == 'e') ADVANCE(179);
      END_STATE();
    case 255:
      if (lookahead == 'e') ADVANCE(520);
      END_STATE();
    case 256:
      if (lookahead == 'e') ADVANCE(571);
      END_STATE();
    case 257:
      if (lookahead == 'e') ADVANCE(572);
      END_STATE();
    case 258:
      if (lookahead == 'e') ADVANCE(573);
      END_STATE();
    case 259:
      if (lookahead == 'e') ADVANCE(538);
      END_STATE();
    case 260:
      if (lookahead == 'e') ADVANCE(402);
      if (lookahead == 'o') ADVANCE(445);
      END_STATE();
    case 261:
      if (lookahead == 'e') ADVANCE(545);
      END_STATE();
    case 262:
      if (lookahead == 'e') ADVANCE(634);
      END_STATE();
    case 263:
      if (lookahead == 'e') ADVANCE(625);
      END_STATE();
    case 264:
      if (lookahead == 'e') ADVANCE(230);
      END_STATE();
    case 265:
      if (lookahead == 'e') ADVANCE(544);
      END_STATE();
    case 266:
      if (lookahead == 'e') ADVANCE(528);
      END_STATE();
    case 267:
      if (lookahead == 'e') ADVANCE(529);
      END_STATE();
    case 268:
      if (lookahead == 'e') ADVANCE(549);
      END_STATE();
    case 269:
      if (lookahead == 'e') ADVANCE(130);
      END_STATE();
    case 270:
      if (lookahead == 'e') ADVANCE(641);
      END_STATE();
    case 271:
      if (lookahead == 'e') ADVANCE(426);
      END_STATE();
    case 272:
      if (lookahead == 'e') ADVANCE(541);
      END_STATE();
    case 273:
      if (lookahead == 'e') ADVANCE(186);
      END_STATE();
    case 274:
      if (lookahead == 'e') ADVANCE(114);
      END_STATE();
    case 275:
      if (lookahead == 'e') ADVANCE(553);
      END_STATE();
    case 276:
      if (lookahead == 'e') ADVANCE(393);
      END_STATE();
    case 277:
      if (lookahead == 'e') ADVANCE(429);
      END_STATE();
    case 278:
      if (lookahead == 'e') ADVANCE(648);
      END_STATE();
    case 279:
      if (lookahead == 'e') ADVANCE(430);
      END_STATE();
    case 280:
      if (lookahead == 'e') ADVANCE(591);
      END_STATE();
    case 281:
      if (lookahead == 'e') ADVANCE(431);
      END_STATE();
    case 282:
      if (lookahead == 'e') ADVANCE(593);
      END_STATE();
    case 283:
      if (lookahead == 'e') ADVANCE(432);
      END_STATE();
    case 284:
      if (lookahead == 'e') ADVANCE(594);
      END_STATE();
    case 285:
      if (lookahead == 'e') ADVANCE(595);
      END_STATE();
    case 286:
      if (lookahead == 'e') ADVANCE(133);
      END_STATE();
    case 287:
      if (lookahead == 'e') ADVANCE(563);
      END_STATE();
    case 288:
      if (lookahead == 'e') ADVANCE(394);
      END_STATE();
    case 289:
      if (lookahead == 'e') ADVANCE(298);
      END_STATE();
    case 290:
      if (lookahead == 'e') ADVANCE(487);
      END_STATE();
    case 291:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(401);
      END_STATE();
    case 292:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(439);
      END_STATE();
    case 293:
      if (lookahead == 'f') ADVANCE(30);
      END_STATE();
    case 294:
      if (lookahead == 'f') ADVANCE(19);
      if (lookahead == 'o') ADVANCE(401);
      END_STATE();
    case 295:
      if (lookahead == 'f') ADVANCE(461);
      END_STATE();
    case 296:
      if (lookahead == 'f') ADVANCE(468);
      END_STATE();
    case 297:
      if (lookahead == 'f') ADVANCE(241);
      if (lookahead == 'q') ADVANCE(668);
      END_STATE();
    case 298:
      if (lookahead == 'f') ADVANCE(241);
      if (lookahead == 'q') ADVANCE(680);
      END_STATE();
    case 299:
      if (lookahead == 'f') ADVANCE(353);
      END_STATE();
    case 300:
      if (lookahead == 'f') ADVANCE(346);
      END_STATE();
    case 301:
      if (lookahead == 'f') ADVANCE(681);
      if (lookahead == 'u') ADVANCE(537);
      END_STATE();
    case 302:
      if (lookahead == 'g') ADVANCE(739);
      END_STATE();
    case 303:
      if (lookahead == 'g') ADVANCE(735);
      END_STATE();
    case 304:
      if (lookahead == 'g') ADVANCE(201);
      if (lookahead == 'm') ADVANCE(446);
      END_STATE();
    case 305:
      if (lookahead == 'g') ADVANCE(222);
      if (lookahead == 's') ADVANCE(524);
      END_STATE();
    case 306:
      if (lookahead == 'g') ADVANCE(679);
      END_STATE();
    case 307:
      if (lookahead == 'g') ADVANCE(227);
      END_STATE();
    case 308:
      if (lookahead == 'g') ADVANCE(276);
      END_STATE();
    case 309:
      if (lookahead == 'g') ADVANCE(258);
      END_STATE();
    case 310:
      if (lookahead == 'g') ADVANCE(277);
      END_STATE();
    case 311:
      if (lookahead == 'g') ADVANCE(290);
      if (lookahead == 's') ADVANCE(540);
      END_STATE();
    case 312:
      if (lookahead == 'g') ADVANCE(288);
      END_STATE();
    case 313:
      if (lookahead == 'h') ADVANCE(744);
      END_STATE();
    case 314:
      if (lookahead == 'h') ADVANCE(745);
      END_STATE();
    case 315:
      if (lookahead == 'h') ADVANCE(791);
      END_STATE();
    case 316:
      if (lookahead == 'h') ADVANCE(807);
      END_STATE();
    case 317:
      if (lookahead == 'h') ADVANCE(809);
      END_STATE();
    case 318:
      if (lookahead == 'h') ADVANCE(224);
      END_STATE();
    case 319:
      if (lookahead == 'h') ADVANCE(534);
      if (lookahead == 'l') ADVANCE(580);
      END_STATE();
    case 320:
      if (lookahead == 'h') ADVANCE(460);
      END_STATE();
    case 321:
      if (lookahead == 'h') ADVANCE(31);
      END_STATE();
    case 322:
      if (lookahead == 'h') ADVANCE(117);
      END_STATE();
    case 323:
      if (lookahead == 'h') ADVANCE(655);
      END_STATE();
    case 324:
      if (lookahead == 'i') ADVANCE(701);
      END_STATE();
    case 325:
      if (lookahead == 'i') ADVANCE(790);
      END_STATE();
    case 326:
      if (lookahead == 'i') ADVANCE(780);
      END_STATE();
    case 327:
      if (lookahead == 'i') ADVANCE(806);
      END_STATE();
    case 328:
      if (lookahead == 'i') ADVANCE(788);
      END_STATE();
    case 329:
      if (lookahead == 'i') ADVANCE(805);
      END_STATE();
    case 330:
      if (lookahead == 'i') ADVANCE(180);
      END_STATE();
    case 331:
      if (lookahead == 'i') ADVANCE(299);
      END_STATE();
    case 332:
      if (lookahead == 'i') ADVANCE(684);
      END_STATE();
    case 333:
      if (lookahead == 'i') ADVANCE(417);
      END_STATE();
    case 334:
      if (lookahead == 'i') ADVANCE(493);
      if (lookahead == 'p') ADVANCE(470);
      END_STATE();
    case 335:
      if (lookahead == 'i') ADVANCE(231);
      END_STATE();
    case 336:
      if (lookahead == 'i') ADVANCE(410);
      END_STATE();
    case 337:
      if (lookahead == 'i') ADVANCE(620);
      END_STATE();
    case 338:
      if (lookahead == 'i') ADVANCE(586);
      END_STATE();
    case 339:
      if (lookahead == 'i') ADVANCE(621);
      END_STATE();
    case 340:
      if (lookahead == 'i') ADVANCE(411);
      END_STATE();
    case 341:
      if (lookahead == 'i') ADVANCE(476);
      END_STATE();
    case 342:
      if (lookahead == 'i') ADVANCE(622);
      END_STATE();
    case 343:
      if (lookahead == 'i') ADVANCE(207);
      END_STATE();
    case 344:
      if (lookahead == 'i') ADVANCE(242);
      END_STATE();
    case 345:
      if (lookahead == 'i') ADVANCE(252);
      END_STATE();
    case 346:
      if (lookahead == 'i') ADVANCE(251);
      END_STATE();
    case 347:
      if (lookahead == 'i') ADVANCE(498);
      END_STATE();
    case 348:
      if (lookahead == 'i') ADVANCE(438);
      END_STATE();
    case 349:
      if (lookahead == 'i') ADVANCE(423);
      END_STATE();
    case 350:
      if (lookahead == 'i') ADVANCE(605);
      END_STATE();
    case 351:
      if (lookahead == 'i') ADVANCE(271);
      END_STATE();
    case 352:
      if (lookahead == 'i') ADVANCE(464);
      END_STATE();
    case 353:
      if (lookahead == 'i') ADVANCE(273);
      END_STATE();
    case 354:
      if (lookahead == 'i') ADVANCE(465);
      END_STATE();
    case 355:
      if (lookahead == 'i') ADVANCE(395);
      END_STATE();
    case 356:
      if (lookahead == 'i') ADVANCE(467);
      END_STATE();
    case 357:
      if (lookahead == 'i') ADVANCE(504);
      END_STATE();
    case 358:
      if (lookahead == 'i') ADVANCE(300);
      END_STATE();
    case 359:
      if (lookahead == 'i') ADVANCE(606);
      END_STATE();
    case 360:
      if (lookahead == 'j') ADVANCE(95);
      if (lookahead == 's') ADVANCE(168);
      if (lookahead == 'v') ADVANCE(265);
      END_STATE();
    case 361:
      if (lookahead == 'j') ADVANCE(583);
      END_STATE();
    case 362:
      if (lookahead == 'j') ADVANCE(94);
      END_STATE();
    case 363:
      if (lookahead == 'k') ADVANCE(664);
      END_STATE();
    case 364:
      if (lookahead == 'k') ADVANCE(250);
      END_STATE();
    case 365:
      if (lookahead == 'k') ADVANCE(343);
      END_STATE();
    case 366:
      if (lookahead == 'k') ADVANCE(235);
      END_STATE();
    case 367:
      if (lookahead == 'k') ADVANCE(345);
      END_STATE();
    case 368:
      if (lookahead == 'l') ADVANCE(820);
      END_STATE();
    case 369:
      if (lookahead == 'l') ADVANCE(65);
      END_STATE();
    case 370:
      if (lookahead == 'l') ADVANCE(335);
      END_STATE();
    case 371:
      if (lookahead == 'l') ADVANCE(577);
      END_STATE();
    case 372:
      if (lookahead == 'l') ADVANCE(689);
      END_STATE();
    case 373:
      if (lookahead == 'l') ADVANCE(108);
      END_STATE();
    case 374:
      if (lookahead == 'l') ADVANCE(326);
      END_STATE();
    case 375:
      if (lookahead == 'l') ADVANCE(74);
      END_STATE();
    case 376:
      if (lookahead == 'l') ADVANCE(375);
      END_STATE();
    case 377:
      if (lookahead == 'l') ADVANCE(118);
      END_STATE();
    case 378:
      if (lookahead == 'l') ADVANCE(675);
      END_STATE();
    case 379:
      if (lookahead == 'l') ADVANCE(351);
      END_STATE();
    case 380:
      if (lookahead == 'l') ADVANCE(77);
      END_STATE();
    case 381:
      if (lookahead == 'l') ADVANCE(380);
      END_STATE();
    case 382:
      if (lookahead == 'l') ADVANCE(85);
      END_STATE();
    case 383:
      if (lookahead == 'm') ADVANCE(775);
      END_STATE();
    case 384:
      if (lookahead == 'm') ADVANCE(113);
      END_STATE();
    case 385:
      if (lookahead == 'm') ADVANCE(324);
      END_STATE();
    case 386:
      if (lookahead == 'm') ADVANCE(62);
      END_STATE();
    case 387:
      if (lookahead == 'm') ADVANCE(239);
      END_STATE();
    case 388:
      if (lookahead == 'm') ADVANCE(262);
      END_STATE();
    case 389:
      if (lookahead == 'm') ADVANCE(256);
      END_STATE();
    case 390:
      if (lookahead == 'm') ADVANCE(72);
      END_STATE();
    case 391:
      if (lookahead == 'm') ADVANCE(596);
      if (lookahead == 's') ADVANCE(243);
      END_STATE();
    case 392:
      if (lookahead == 'm') ADVANCE(503);
      END_STATE();
    case 393:
      if (lookahead == 'm') ADVANCE(279);
      END_STATE();
    case 394:
      if (lookahead == 'm') ADVANCE(283);
      END_STATE();
    case 395:
      if (lookahead == 'm') ADVANCE(284);
      END_STATE();
    case 396:
      if (lookahead == 'm') ADVANCE(135);
      END_STATE();
    case 397:
      if (lookahead == 'n') ADVANCE(171);
      END_STATE();
    case 398:
      if (lookahead == 'n') ADVANCE(705);
      END_STATE();
    case 399:
      if (lookahead == 'n') ADVANCE(705);
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 400:
      if (lookahead == 'n') ADVANCE(705);
      if (lookahead == 'p') ADVANCE(33);
      END_STATE();
    case 401:
      if (lookahead == 'n') ADVANCE(158);
      END_STATE();
    case 402:
      if (lookahead == 'n') ADVANCE(743);
      END_STATE();
    case 403:
      if (lookahead == 'n') ADVANCE(760);
      END_STATE();
    case 404:
      if (lookahead == 'n') ADVANCE(698);
      END_STATE();
    case 405:
      if (lookahead == 'n') ADVANCE(797);
      END_STATE();
    case 406:
      if (lookahead == 'n') ADVANCE(794);
      END_STATE();
    case 407:
      if (lookahead == 'n') ADVANCE(819);
      END_STATE();
    case 408:
      if (lookahead == 'n') ADVANCE(172);
      END_STATE();
    case 409:
      if (lookahead == 'n') ADVANCE(172);
      if (lookahead == 'q') ADVANCE(715);
      END_STATE();
    case 410:
      if (lookahead == 'n') ADVANCE(302);
      END_STATE();
    case 411:
      if (lookahead == 'n') ADVANCE(303);
      END_STATE();
    case 412:
      if (lookahead == 'n') ADVANCE(665);
      END_STATE();
    case 413:
      if (lookahead == 'n') ADVANCE(306);
      END_STATE();
    case 414:
      if (lookahead == 'n') ADVANCE(455);
      END_STATE();
    case 415:
      if (lookahead == 'n') ADVANCE(182);
      END_STATE();
    case 416:
      if (lookahead == 'n') ADVANCE(101);
      END_STATE();
    case 417:
      if (lookahead == 'n') ADVANCE(566);
      END_STATE();
    case 418:
      if (lookahead == 'n') ADVANCE(124);
      END_STATE();
    case 419:
      if (lookahead == 'n') ADVANCE(66);
      END_STATE();
    case 420:
      if (lookahead == 'n') ADVANCE(162);
      END_STATE();
    case 421:
      if (lookahead == 'n') ADVANCE(631);
      END_STATE();
    case 422:
      if (lookahead == 'n') ADVANCE(248);
      END_STATE();
    case 423:
      if (lookahead == 'n') ADVANCE(71);
      END_STATE();
    case 424:
      if (lookahead == 'n') ADVANCE(32);
      END_STATE();
    case 425:
      if (lookahead == 'n') ADVANCE(58);
      END_STATE();
    case 426:
      if (lookahead == 'n') ADVANCE(639);
      END_STATE();
    case 427:
      if (lookahead == 'n') ADVANCE(653);
      if (lookahead == 'u') ADVANCE(437);
      END_STATE();
    case 428:
      if (lookahead == 'n') ADVANCE(75);
      END_STATE();
    case 429:
      if (lookahead == 'n') ADVANCE(613);
      END_STATE();
    case 430:
      if (lookahead == 'n') ADVANCE(638);
      END_STATE();
    case 431:
      if (lookahead == 'n') ADVANCE(614);
      END_STATE();
    case 432:
      if (lookahead == 'n') ADVANCE(646);
      END_STATE();
    case 433:
      if (lookahead == 'n') ADVANCE(623);
      END_STATE();
    case 434:
      if (lookahead == 'n') ADVANCE(216);
      END_STATE();
    case 435:
      if (lookahead == 'n') ADVANCE(132);
      if (lookahead == 't') ADVANCE(530);
      if (lookahead == 'v') ADVANCE(112);
      END_STATE();
    case 436:
      if (lookahead == 'n') ADVANCE(132);
      if (lookahead == 'v') ADVANCE(112);
      END_STATE();
    case 437:
      if (lookahead == 'n') ADVANCE(642);
      END_STATE();
    case 438:
      if (lookahead == 'n') ADVANCE(281);
      END_STATE();
    case 439:
      if (lookahead == 'n') ADVANCE(157);
      END_STATE();
    case 440:
      if (lookahead == 'n') ADVANCE(354);
      END_STATE();
    case 441:
      if (lookahead == 'n') ADVANCE(134);
      END_STATE();
    case 442:
      if (lookahead == 'n') ADVANCE(88);
      END_STATE();
    case 443:
      if (lookahead == 'o') ADVANCE(63);
      END_STATE();
    case 444:
      if (lookahead == 'o') ADVANCE(63);
      if (lookahead == 'r') ADVANCE(662);
      END_STATE();
    case 445:
      if (lookahead == 'o') ADVANCE(363);
      if (lookahead == 'w') ADVANCE(221);
      END_STATE();
    case 446:
      if (lookahead == 'o') ADVANCE(683);
      END_STATE();
    case 447:
      if (lookahead == 'o') ADVANCE(427);
      END_STATE();
    case 448:
      if (lookahead == 'o') ADVANCE(517);
      END_STATE();
    case 449:
      if (lookahead == 'o') ADVANCE(693);
      END_STATE();
    case 450:
      if (lookahead == 'o') ADVANCE(390);
      END_STATE();
    case 451:
      if (lookahead == 'o') ADVANCE(365);
      END_STATE();
    case 452:
      if (lookahead == 'o') ADVANCE(608);
      END_STATE();
    case 453:
      if (lookahead == 'o') ADVANCE(364);
      END_STATE();
    case 454:
      if (lookahead == 'o') ADVANCE(347);
      END_STATE();
    case 455:
      if (lookahead == 'o') ADVANCE(404);
      END_STATE();
    case 456:
      if (lookahead == 'o') ADVANCE(624);
      END_STATE();
    case 457:
      if (lookahead == 'o') ADVANCE(523);
      END_STATE();
    case 458:
      if (lookahead == 'o') ADVANCE(628);
      END_STATE();
    case 459:
      if (lookahead == 'o') ADVANCE(451);
      END_STATE();
    case 460:
      if (lookahead == 'o') ADVANCE(175);
      END_STATE();
    case 461:
      if (lookahead == 'o') ADVANCE(562);
      END_STATE();
    case 462:
      if (lookahead == 'o') ADVANCE(83);
      END_STATE();
    case 463:
      if (lookahead == 'o') ADVANCE(442);
      END_STATE();
    case 464:
      if (lookahead == 'o') ADVANCE(406);
      END_STATE();
    case 465:
      if (lookahead == 'o') ADVANCE(407);
      END_STATE();
    case 466:
      if (lookahead == 'o') ADVANCE(612);
      END_STATE();
    case 467:
      if (lookahead == 'o') ADVANCE(424);
      END_STATE();
    case 468:
      if (lookahead == 'o') ADVANCE(522);
      END_STATE();
    case 469:
      if (lookahead == 'o') ADVANCE(616);
      END_STATE();
    case 470:
      if (lookahead == 'o') ADVANCE(552);
      END_STATE();
    case 471:
      if (lookahead == 'o') ADVANCE(581);
      END_STATE();
    case 472:
      if (lookahead == 'o') ADVANCE(184);
      END_STATE();
    case 473:
      if (lookahead == 'o') ADVANCE(505);
      END_STATE();
    case 474:
      if (lookahead == 'o') ADVANCE(588);
      END_STATE();
    case 475:
      if (lookahead == 'o') ADVANCE(434);
      END_STATE();
    case 476:
      if (lookahead == 'o') ADVANCE(425);
      END_STATE();
    case 477:
      if (lookahead == 'o') ADVANCE(590);
      END_STATE();
    case 478:
      if (lookahead == 'o') ADVANCE(188);
      END_STATE();
    case 479:
      if (lookahead == 'o') ADVANCE(189);
      END_STATE();
    case 480:
      if (lookahead == 'o') ADVANCE(550);
      END_STATE();
    case 481:
      if (lookahead == 'o') ADVANCE(551);
      END_STATE();
    case 482:
      if (lookahead == 'o') ADVANCE(191);
      END_STATE();
    case 483:
      if (lookahead == 'o') ADVANCE(433);
      END_STATE();
    case 484:
      if (lookahead == 'o') ADVANCE(192);
      END_STATE();
    case 485:
      if (lookahead == 'o') ADVANCE(555);
      END_STATE();
    case 486:
      if (lookahead == 'o') ADVANCE(367);
      END_STATE();
    case 487:
      if (lookahead == 'o') ADVANCE(357);
      END_STATE();
    case 488:
      if (lookahead == 'o') ADVANCE(486);
      END_STATE();
    case 489:
      if (lookahead == 'o') ADVANCE(86);
      END_STATE();
    case 490:
      if (lookahead == 'o') ADVANCE(87);
      END_STATE();
    case 491:
      if (lookahead == 'o') ADVANCE(661);
      END_STATE();
    case 492:
      if (lookahead == 'p') ADVANCE(506);
      if (lookahead == 'r') ADVANCE(369);
      if (lookahead == 'u') ADVANCE(330);
      END_STATE();
    case 493:
      if (lookahead == 'p') ADVANCE(784);
      END_STATE();
    case 494:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 495:
      if (lookahead == 'p') ADVANCE(403);
      END_STATE();
    case 496:
      if (lookahead == 'p') ADVANCE(7);
      END_STATE();
    case 497:
      if (lookahead == 'p') ADVANCE(373);
      END_STATE();
    case 498:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 499:
      if (lookahead == 'p') ADVANCE(41);
      END_STATE();
    case 500:
      if (lookahead == 'p') ADVANCE(55);
      END_STATE();
    case 501:
      if (lookahead == 'p') ADVANCE(229);
      END_STATE();
    case 502:
      if (lookahead == 'p') ADVANCE(535);
      END_STATE();
    case 503:
      if (lookahead == 'p') ADVANCE(13);
      END_STATE();
    case 504:
      if (lookahead == 'p') ADVANCE(20);
      END_STATE();
    case 505:
      if (lookahead == 'p') ADVANCE(269);
      END_STATE();
    case 506:
      if (lookahead == 'p') ADVANCE(226);
      END_STATE();
    case 507:
      if (lookahead == 'p') ADVANCE(119);
      END_STATE();
    case 508:
      if (lookahead == 'p') ADVANCE(647);
      END_STATE();
    case 509:
      if (lookahead == 'p') ADVANCE(121);
      if (lookahead == 'q') ADVANCE(676);
      END_STATE();
    case 510:
      if (lookahead == 'p') ADVANCE(122);
      if (lookahead == 'q') ADVANCE(677);
      END_STATE();
    case 511:
      if (lookahead == 'p') ADVANCE(598);
      END_STATE();
    case 512:
      if (lookahead == 'p') ADVANCE(43);
      END_STATE();
    case 513:
      if (lookahead == 'q') ADVANCE(715);
      END_STATE();
    case 514:
      if (lookahead == 'q') ADVANCE(374);
      END_STATE();
    case 515:
      if (lookahead == 'q') ADVANCE(678);
      END_STATE();
    case 516:
      if (lookahead == 'r') ADVANCE(710);
      END_STATE();
    case 517:
      if (lookahead == 'r') ADVANCE(708);
      END_STATE();
    case 518:
      if (lookahead == 'r') ADVANCE(736);
      END_STATE();
    case 519:
      if (lookahead == 'r') ADVANCE(740);
      END_STATE();
    case 520:
      if (lookahead == 'r') ADVANCE(760);
      END_STATE();
    case 521:
      if (lookahead == 'r') ADVANCE(787);
      END_STATE();
    case 522:
      if (lookahead == 'r') ADVANCE(795);
      END_STATE();
    case 523:
      if (lookahead == 'r') ADVANCE(366);
      END_STATE();
    case 524:
      if (lookahead == 'r') ADVANCE(143);
      END_STATE();
    case 525:
      if (lookahead == 'r') ADVANCE(686);
      END_STATE();
    case 526:
      if (lookahead == 'r') ADVANCE(695);
      END_STATE();
    case 527:
      if (lookahead == 'r') ADVANCE(658);
      END_STATE();
    case 528:
      if (lookahead == 'r') ADVANCE(696);
      END_STATE();
    case 529:
      if (lookahead == 'r') ADVANCE(697);
      END_STATE();
    case 530:
      if (lookahead == 'r') ADVANCE(669);
      END_STATE();
    case 531:
      if (lookahead == 'r') ADVANCE(325);
      END_STATE();
    case 532:
      if (lookahead == 'r') ADVANCE(39);
      END_STATE();
    case 533:
      if (lookahead == 'r') ADVANCE(82);
      END_STATE();
    case 534:
      if (lookahead == 'r') ADVANCE(274);
      END_STATE();
    case 535:
      if (lookahead == 'r') ADVANCE(449);
      END_STATE();
    case 536:
      if (lookahead == 'r') ADVANCE(462);
      END_STATE();
    case 537:
      if (lookahead == 'r') ADVANCE(327);
      END_STATE();
    case 538:
      if (lookahead == 'r') ADVANCE(585);
      END_STATE();
    case 539:
      if (lookahead == 'r') ADVANCE(223);
      END_STATE();
    case 540:
      if (lookahead == 'r') ADVANCE(152);
      END_STATE();
    case 541:
      if (lookahead == 'r') ADVANCE(57);
      END_STATE();
    case 542:
      if (lookahead == 'r') ADVANCE(328);
      END_STATE();
    case 543:
      if (lookahead == 'r') ADVANCE(473);
      END_STATE();
    case 544:
      if (lookahead == 'r') ADVANCE(331);
      END_STATE();
    case 545:
      if (lookahead == 'r') ADVANCE(570);
      END_STATE();
    case 546:
      if (lookahead == 'r') ADVANCE(329);
      END_STATE();
    case 547:
      if (lookahead == 'r') ADVANCE(204);
      END_STATE();
    case 548:
      if (lookahead == 'r') ADVANCE(208);
      END_STATE();
    case 549:
      if (lookahead == 'r') ADVANCE(575);
      END_STATE();
    case 550:
      if (lookahead == 'r') ADVANCE(209);
      END_STATE();
    case 551:
      if (lookahead == 'r') ADVANCE(211);
      END_STATE();
    case 552:
      if (lookahead == 'r') ADVANCE(615);
      END_STATE();
    case 553:
      if (lookahead == 'r') ADVANCE(644);
      END_STATE();
    case 554:
      if (lookahead == 'r') ADVANCE(244);
      END_STATE();
    case 555:
      if (lookahead == 'r') ADVANCE(215);
      END_STATE();
    case 556:
      if (lookahead == 'r') ADVANCE(225);
      if (lookahead == 'v') ADVANCE(287);
      END_STATE();
    case 557:
      if (lookahead == 'r') ADVANCE(336);
      END_STATE();
    case 558:
      if (lookahead == 'r') ADVANCE(154);
      if (lookahead == 's') ADVANCE(514);
      if (lookahead == 'x') ADVANCE(587);
      END_STATE();
    case 559:
      if (lookahead == 'r') ADVANCE(187);
      END_STATE();
    case 560:
      if (lookahead == 'r') ADVANCE(340);
      END_STATE();
    case 561:
      if (lookahead == 'r') ADVANCE(253);
      END_STATE();
    case 562:
      if (lookahead == 'r') ADVANCE(690);
      END_STATE();
    case 563:
      if (lookahead == 'r') ADVANCE(358);
      END_STATE();
    case 564:
      if (lookahead == 's') ADVANCE(760);
      END_STATE();
    case 565:
      if (lookahead == 's') ADVANCE(729);
      END_STATE();
    case 566:
      if (lookahead == 's') ADVANCE(728);
      END_STATE();
    case 567:
      if (lookahead == 's') ADVANCE(738);
      END_STATE();
    case 568:
      if (lookahead == 's') ADVANCE(781);
      END_STATE();
    case 569:
      if (lookahead == 's') ADVANCE(813);
      END_STATE();
    case 570:
      if (lookahead == 's') ADVANCE(814);
      END_STATE();
    case 571:
      if (lookahead == 's') ADVANCE(816);
      END_STATE();
    case 572:
      if (lookahead == 's') ADVANCE(817);
      END_STATE();
    case 573:
      if (lookahead == 's') ADVANCE(818);
      END_STATE();
    case 574:
      if (lookahead == 's') ADVANCE(368);
      if (lookahead == 't') ADVANCE(99);
      END_STATE();
    case 575:
      if (lookahead == 's') ADVANCE(815);
      END_STATE();
    case 576:
      if (lookahead == 's') ADVANCE(60);
      END_STATE();
    case 577:
      if (lookahead == 's') ADVANCE(203);
      END_STATE();
    case 578:
      if (lookahead == 's') ADVANCE(160);
      END_STATE();
    case 579:
      if (lookahead == 's') ADVANCE(630);
      END_STATE();
    case 580:
      if (lookahead == 's') ADVANCE(64);
      END_STATE();
    case 581:
      if (lookahead == 's') ADVANCE(633);
      END_STATE();
    case 582:
      if (lookahead == 's') ADVANCE(317);
      END_STATE();
    case 583:
      if (lookahead == 's') ADVANCE(463);
      END_STATE();
    case 584:
      if (lookahead == 's') ADVANCE(76);
      END_STATE();
    case 585:
      if (lookahead == 's') ADVANCE(352);
      END_STATE();
    case 586:
      if (lookahead == 's') ADVANCE(341);
      END_STATE();
    case 587:
      if (lookahead == 's') ADVANCE(568);
      END_STATE();
    case 588:
      if (lookahead == 's') ADVANCE(610);
      END_STATE();
    case 589:
      if (lookahead == 's') ADVANCE(412);
      END_STATE();
    case 590:
      if (lookahead == 's') ADVANCE(650);
      END_STATE();
    case 591:
      if (lookahead == 's') ADVANCE(635);
      END_STATE();
    case 592:
      if (lookahead == 's') ADVANCE(264);
      END_STATE();
    case 593:
      if (lookahead == 's') ADVANCE(636);
      END_STATE();
    case 594:
      if (lookahead == 's') ADVANCE(640);
      END_STATE();
    case 595:
      if (lookahead == 's') ADVANCE(643);
      END_STATE();
    case 596:
      if (lookahead == 's') ADVANCE(246);
      END_STATE();
    case 597:
      if (lookahead == 's') ADVANCE(254);
      END_STATE();
    case 598:
      if (lookahead == 's') ADVANCE(654);
      END_STATE();
    case 599:
      if (lookahead == 's') ADVANCE(238);
      END_STATE();
    case 600:
      if (lookahead == 's') ADVANCE(597);
      END_STATE();
    case 601:
      if (lookahead == 's') ADVANCE(249);
      END_STATE();
    case 602:
      if (lookahead == 's') ADVANCE(79);
      END_STATE();
    case 603:
      if (lookahead == 's') ADVANCE(166);
      END_STATE();
    case 604:
      if (lookahead == 's') ADVANCE(656);
      END_STATE();
    case 605:
      if (lookahead == 's') ADVANCE(489);
      END_STATE();
    case 606:
      if (lookahead == 's') ADVANCE(490);
      END_STATE();
    case 607:
      if (lookahead == 't') ADVANCE(142);
      END_STATE();
    case 608:
      if (lookahead == 't') ADVANCE(765);
      END_STATE();
    case 609:
      if (lookahead == 't') ADVANCE(731);
      END_STATE();
    case 610:
      if (lookahead == 't') ADVANCE(786);
      END_STATE();
    case 611:
      if (lookahead == 't') ADVANCE(796);
      END_STATE();
    case 612:
      if (lookahead == 't') ADVANCE(823);
      END_STATE();
    case 613:
      if (lookahead == 't') ADVANCE(793);
      END_STATE();
    case 614:
      if (lookahead == 't') ADVANCE(801);
      END_STATE();
    case 615:
      if (lookahead == 't') ADVANCE(777);
      END_STATE();
    case 616:
      if (lookahead == 't') ADVANCE(821);
      END_STATE();
    case 617:
      if (lookahead == 't') ADVANCE(618);
      END_STATE();
    case 618:
      if (lookahead == 't') ADVANCE(496);
      END_STATE();
    case 619:
      if (lookahead == 't') ADVANCE(99);
      END_STATE();
    case 620:
      if (lookahead == 't') ADVANCE(313);
      END_STATE();
    case 621:
      if (lookahead == 't') ADVANCE(694);
      END_STATE();
    case 622:
      if (lookahead == 't') ADVANCE(314);
      END_STATE();
    case 623:
      if (lookahead == 't') ADVANCE(100);
      END_STATE();
    case 624:
      if (lookahead == 't') ADVANCE(54);
      END_STATE();
    case 625:
      if (lookahead == 't') ADVANCE(320);
      END_STATE();
    case 626:
      if (lookahead == 't') ADVANCE(149);
      END_STATE();
    case 627:
      if (lookahead == 't') ADVANCE(321);
      END_STATE();
    case 628:
      if (lookahead == 't') ADVANCE(422);
      END_STATE();
    case 629:
      if (lookahead == 't') ADVANCE(315);
      END_STATE();
    case 630:
      if (lookahead == 't') ADVANCE(557);
      END_STATE();
    case 631:
      if (lookahead == 't') ADVANCE(24);
      END_STATE();
    case 632:
      if (lookahead == 't') ADVANCE(316);
      END_STATE();
    case 633:
      if (lookahead == 't') ADVANCE(416);
      END_STATE();
    case 634:
      if (lookahead == 't') ADVANCE(110);
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
      if (lookahead == 't') ADVANCE(68);
      END_STATE();
    case 640:
      if (lookahead == 't') ADVANCE(106);
      END_STATE();
    case 641:
      if (lookahead == 't') ADVANCE(536);
      END_STATE();
    case 642:
      if (lookahead == 't') ADVANCE(526);
      END_STATE();
    case 643:
      if (lookahead == 't') ADVANCE(21);
      END_STATE();
    case 644:
      if (lookahead == 't') ADVANCE(59);
      END_STATE();
    case 645:
      if (lookahead == 't') ADVANCE(236);
      END_STATE();
    case 646:
      if (lookahead == 't') ADVANCE(23);
      END_STATE();
    case 647:
      if (lookahead == 't') ADVANCE(245);
      END_STATE();
    case 648:
      if (lookahead == 't') ADVANCE(237);
      END_STATE();
    case 649:
      if (lookahead == 't') ADVANCE(247);
      END_STATE();
    case 650:
      if (lookahead == 't') ADVANCE(105);
      END_STATE();
    case 651:
      if (lookahead == 't') ADVANCE(84);
      END_STATE();
    case 652:
      if (lookahead == 't') ADVANCE(499);
      END_STATE();
    case 653:
      if (lookahead == 't') ADVANCE(348);
      END_STATE();
    case 654:
      if (lookahead == 't') ADVANCE(554);
      END_STATE();
    case 655:
      if (lookahead == 't') ADVANCE(652);
      END_STATE();
    case 656:
      if (lookahead == 't') ADVANCE(560);
      END_STATE();
    case 657:
      if (lookahead == 't') ADVANCE(356);
      END_STATE();
    case 658:
      if (lookahead == 't') ADVANCE(602);
      END_STATE();
    case 659:
      if (lookahead == 't') ADVANCE(512);
      END_STATE();
    case 660:
      if (lookahead == 't') ADVANCE(659);
      END_STATE();
    case 661:
      if (lookahead == 't') ADVANCE(89);
      END_STATE();
    case 662:
      if (lookahead == 'u') ADVANCE(202);
      END_STATE();
    case 663:
      if (lookahead == 'u') ADVANCE(138);
      END_STATE();
    case 664:
      if (lookahead == 'u') ADVANCE(500);
      END_STATE();
    case 665:
      if (lookahead == 'u') ADVANCE(383);
      END_STATE();
    case 666:
      if (lookahead == 'u') ADVANCE(511);
      END_STATE();
    case 667:
      if (lookahead == 'u') ADVANCE(376);
      END_STATE();
    case 668:
      if (lookahead == 'u') ADVANCE(280);
      END_STATE();
    case 669:
      if (lookahead == 'u') ADVANCE(420);
      END_STATE();
    case 670:
      if (lookahead == 'u') ADVANCE(440);
      END_STATE();
    case 671:
      if (lookahead == 'u') ADVANCE(543);
      END_STATE();
    case 672:
      if (lookahead == 'u') ADVANCE(542);
      END_STATE();
    case 673:
      if (lookahead == 'u') ADVANCE(627);
      END_STATE();
    case 674:
      if (lookahead == 'u') ADVANCE(546);
      END_STATE();
    case 675:
      if (lookahead == 'u') ADVANCE(257);
      END_STATE();
    case 676:
      if (lookahead == 'u') ADVANCE(266);
      END_STATE();
    case 677:
      if (lookahead == 'u') ADVANCE(267);
      END_STATE();
    case 678:
      if (lookahead == 'u') ADVANCE(282);
      END_STATE();
    case 679:
      if (lookahead == 'u') ADVANCE(129);
      END_STATE();
    case 680:
      if (lookahead == 'u') ADVANCE(285);
      END_STATE();
    case 681:
      if (lookahead == 'u') ADVANCE(381);
      END_STATE();
    case 682:
      if (lookahead == 'v') ADVANCE(49);
      END_STATE();
    case 683:
      if (lookahead == 'v') ADVANCE(233);
      END_STATE();
    case 684:
      if (lookahead == 'v') ADVANCE(338);
      END_STATE();
    case 685:
      if (lookahead == 'v') ADVANCE(453);
      END_STATE();
    case 686:
      if (lookahead == 'v') ADVANCE(272);
      END_STATE();
    case 687:
      if (lookahead == 'w') ADVANCE(22);
      END_STATE();
    case 688:
      if (lookahead == 'w') ADVANCE(337);
      END_STATE();
    case 689:
      if (lookahead == 'w') ADVANCE(128);
      END_STATE();
    case 690:
      if (lookahead == 'w') ADVANCE(116);
      END_STATE();
    case 691:
      if (lookahead == 'w') ADVANCE(342);
      END_STATE();
    case 692:
      if (lookahead == 'x') ADVANCE(73);
      END_STATE();
    case 693:
      if (lookahead == 'x') ADVANCE(344);
      END_STATE();
    case 694:
      if (lookahead == 'y') ADVANCE(798);
      END_STATE();
    case 695:
      if (lookahead == 'y') ADVANCE(802);
      END_STATE();
    case 696:
      if (lookahead == 'y') ADVANCE(792);
      END_STATE();
    case 697:
      if (lookahead == 'y') ADVANCE(808);
      END_STATE();
    case 698:
      if (lookahead == 'y') ADVANCE(385);
      END_STATE();
    case 699:
      if (lookahead == 'y') ADVANCE(645);
      END_STATE();
    case 700:
      if (lookahead == 'z') ADVANCE(475);
      END_STATE();
    case 701:
      if (lookahead == 'z') ADVANCE(255);
      END_STATE();
    case 702:
      if (lookahead == '|') ADVANCE(711);
      END_STATE();
    case 703:
      if (eof) ADVANCE(704);
      if (lookahead == '!') ADVANCE(766);
      if (lookahead == '"') ADVANCE(3);
      if (lookahead == '#') ADVANCE(714);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(732);
      if (lookahead == ')') ADVANCE(734);
      if (lookahead == ',') ADVANCE(733);
      if (lookahead == '/') ADVANCE(756);
      if (lookahead == '2') ADVANCE(15);
      if (lookahead == '[') ADVANCE(768);
      if (lookahead == '^') ADVANCE(53);
      if (lookahead == 'a') ADVANCE(397);
      if (lookahead == 'c') ADVANCE(292);
      if (lookahead == 'e') ADVANCE(408);
      if (lookahead == 'f') ADVANCE(91);
      if (lookahead == 'h') ADVANCE(617);
      if (lookahead == 'i') ADVANCE(494);
      if (lookahead == 'l') ADVANCE(260);
      if (lookahead == 'n') ADVANCE(452);
      if (lookahead == 'o') ADVANCE(516);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == 's') ADVANCE(574);
      if (lookahead == 't') ADVANCE(444);
      if (lookahead == 'u') ADVANCE(492);
      if (lookahead == 'x') ADVANCE(448);
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
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(747);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(747);
      END_STATE();
    case 747:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(747);
      END_STATE();
    case 748:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 749:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 750:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 751:
      ACCEPT_TOKEN(sym_ipv4);
      END_STATE();
    case 752:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '5') ADVANCE(753);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(751);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(754);
      END_STATE();
    case 753:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(751);
      END_STATE();
    case 754:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(751);
      END_STATE();
    case 755:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(754);
      END_STATE();
    case 756:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 757:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      END_STATE();
    case 758:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(757);
      END_STATE();
    case 759:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(757);
      END_STATE();
    case 760:
      ACCEPT_TOKEN(sym_ip_list);
      END_STATE();
    case 761:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == '.') ADVANCE(97);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(764);
      END_STATE();
    case 762:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'c') ADVANCE(763);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(764);
      END_STATE();
    case 763:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'f') ADVANCE(761);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(764);
      END_STATE();
    case 764:
      ACCEPT_TOKEN(sym_ip_list);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(764);
      END_STATE();
    case 765:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 766:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 767:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(723);
      END_STATE();
    case 768:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 769:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      if (lookahead == '*') ADVANCE(52);
      END_STATE();
    case 770:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 771:
      ACCEPT_TOKEN(anon_sym_STAR);
      END_STATE();
    case 772:
      ACCEPT_TOKEN(anon_sym_LBRACK_STAR_RBRACK);
      END_STATE();
    case 773:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 774:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 775:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 776:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 777:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 778:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 779:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(558);
      END_STATE();
    case 780:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 781:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 782:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 783:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(159);
      END_STATE();
    case 784:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 785:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 786:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 787:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 788:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 789:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 790:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(509);
      END_STATE();
    case 791:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 792:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 793:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 794:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 795:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 796:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 797:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 798:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 799:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 800:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 801:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 802:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 803:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 804:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 805:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 806:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(510);
      END_STATE();
    case 807:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 808:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 809:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 810:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 811:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 812:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 813:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 814:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(435);
      END_STATE();
    case 815:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(436);
      END_STATE();
    case 816:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTnames);
      END_STATE();
    case 817:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTvalues);
      END_STATE();
    case 818:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTaccepted_languages);
      END_STATE();
    case 819:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 820:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 821:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 822:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 823:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 824:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 825:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_verified);
      END_STATE();
    case 826:
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
  [42] = {.lex_state = 1},
  [43] = {.lex_state = 1},
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
  [64] = {.lex_state = 703},
  [65] = {.lex_state = 703},
  [66] = {.lex_state = 703},
  [67] = {.lex_state = 703},
  [68] = {.lex_state = 703},
  [69] = {.lex_state = 703},
  [70] = {.lex_state = 703},
  [71] = {.lex_state = 703},
  [72] = {.lex_state = 703},
  [73] = {.lex_state = 703},
  [74] = {.lex_state = 703},
  [75] = {.lex_state = 703},
  [76] = {.lex_state = 703},
  [77] = {.lex_state = 703},
  [78] = {.lex_state = 703},
  [79] = {.lex_state = 703},
  [80] = {.lex_state = 2},
  [81] = {.lex_state = 2},
  [82] = {.lex_state = 2},
  [83] = {.lex_state = 2},
  [84] = {.lex_state = 2},
  [85] = {.lex_state = 2},
  [86] = {.lex_state = 2},
  [87] = {.lex_state = 2},
  [88] = {.lex_state = 2},
  [89] = {.lex_state = 2},
  [90] = {.lex_state = 2},
  [91] = {.lex_state = 2},
  [92] = {.lex_state = 2},
  [93] = {.lex_state = 2},
  [94] = {.lex_state = 2},
  [95] = {.lex_state = 0},
  [96] = {.lex_state = 1},
  [97] = {.lex_state = 703},
  [98] = {.lex_state = 1},
  [99] = {.lex_state = 703},
  [100] = {.lex_state = 703},
  [101] = {.lex_state = 1},
  [102] = {.lex_state = 1},
  [103] = {.lex_state = 1},
  [104] = {.lex_state = 1},
  [105] = {.lex_state = 1},
  [106] = {.lex_state = 1},
  [107] = {.lex_state = 1},
  [108] = {.lex_state = 703},
  [109] = {.lex_state = 1},
  [110] = {.lex_state = 1},
  [111] = {.lex_state = 1},
  [112] = {.lex_state = 0},
  [113] = {.lex_state = 1},
  [114] = {.lex_state = 1},
  [115] = {.lex_state = 0},
  [116] = {.lex_state = 0},
  [117] = {.lex_state = 1},
  [118] = {.lex_state = 0},
  [119] = {.lex_state = 0},
  [120] = {.lex_state = 0},
  [121] = {.lex_state = 0},
  [122] = {.lex_state = 0},
  [123] = {.lex_state = 0},
  [124] = {.lex_state = 0},
  [125] = {.lex_state = 0},
  [126] = {.lex_state = 0},
  [127] = {.lex_state = 0},
  [128] = {.lex_state = 1},
  [129] = {.lex_state = 0},
  [130] = {.lex_state = 0},
  [131] = {.lex_state = 0},
  [132] = {.lex_state = 0},
  [133] = {.lex_state = 0},
  [134] = {.lex_state = 0},
  [135] = {.lex_state = 0},
  [136] = {.lex_state = 0},
  [137] = {.lex_state = 0},
  [138] = {.lex_state = 0},
  [139] = {.lex_state = 0},
  [140] = {.lex_state = 0},
  [141] = {.lex_state = 0},
  [142] = {.lex_state = 0},
  [143] = {.lex_state = 0},
  [144] = {.lex_state = 703},
  [145] = {.lex_state = 0},
  [146] = {.lex_state = 0},
  [147] = {.lex_state = 0},
  [148] = {.lex_state = 0},
  [149] = {.lex_state = 0},
  [150] = {.lex_state = 0},
  [151] = {.lex_state = 0},
  [152] = {.lex_state = 703},
  [153] = {.lex_state = 1},
  [154] = {.lex_state = 0},
  [155] = {.lex_state = 0},
  [156] = {.lex_state = 0},
  [157] = {.lex_state = 0},
  [158] = {.lex_state = 2},
  [159] = {.lex_state = 703},
  [160] = {.lex_state = 0},
  [161] = {.lex_state = 0},
  [162] = {.lex_state = 0},
  [163] = {.lex_state = 0},
  [164] = {.lex_state = 0},
  [165] = {.lex_state = 0},
  [166] = {.lex_state = 0},
  [167] = {.lex_state = 703},
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
  [185] = {.lex_state = 0},
  [186] = {.lex_state = 0},
  [187] = {.lex_state = 1},
  [188] = {.lex_state = 703},
  [189] = {.lex_state = 0},
  [190] = {.lex_state = 0},
  [191] = {.lex_state = 0},
  [192] = {.lex_state = 0},
  [193] = {.lex_state = 703},
  [194] = {.lex_state = 703},
  [195] = {.lex_state = 703},
  [196] = {.lex_state = 703},
  [197] = {.lex_state = 0},
  [198] = {.lex_state = 0},
  [199] = {.lex_state = 0},
  [200] = {.lex_state = 0},
  [201] = {.lex_state = 703},
  [202] = {.lex_state = 703},
  [203] = {.lex_state = 0},
  [204] = {.lex_state = 0},
  [205] = {.lex_state = 0},
  [206] = {.lex_state = 0},
  [207] = {.lex_state = 0},
  [208] = {.lex_state = 0},
  [209] = {.lex_state = 703},
  [210] = {.lex_state = 0},
  [211] = {.lex_state = 0},
  [212] = {.lex_state = 0},
  [213] = {.lex_state = 0},
  [214] = {.lex_state = 0},
  [215] = {.lex_state = 703},
  [216] = {.lex_state = 0},
  [217] = {.lex_state = 0},
  [218] = {.lex_state = 0},
  [219] = {.lex_state = 0},
  [220] = {.lex_state = 0},
  [221] = {.lex_state = 0},
  [222] = {.lex_state = 0},
  [223] = {.lex_state = 0},
  [224] = {.lex_state = 0},
  [225] = {.lex_state = 0},
  [226] = {.lex_state = 0},
  [227] = {.lex_state = 0},
  [228] = {.lex_state = 0},
  [229] = {.lex_state = 0},
  [230] = {.lex_state = 0},
  [231] = {.lex_state = 0},
  [232] = {.lex_state = 0},
  [233] = {.lex_state = 0},
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
    [anon_sym_LBRACK_STAR_RBRACK] = ACTIONS(1),
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
    [sym_source_file] = STATE(197),
    [sym__expression] = STATE(40),
    [sym_not_expression] = STATE(40),
    [sym_in_expression] = STATE(40),
    [sym_compound_expression] = STATE(40),
    [sym_simple_expression] = STATE(40),
    [sym__bool_lhs] = STATE(40),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(40),
    [sym_group] = STATE(40),
    [sym_boolean] = STATE(40),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(40),
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
    [sym__expression] = STATE(40),
    [sym_not_expression] = STATE(40),
    [sym_in_expression] = STATE(40),
    [sym_compound_expression] = STATE(40),
    [sym_simple_expression] = STATE(40),
    [sym__bool_lhs] = STATE(40),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(40),
    [sym_group] = STATE(40),
    [sym_boolean] = STATE(40),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(40),
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
    [sym__expression] = STATE(40),
    [sym_not_expression] = STATE(40),
    [sym_in_expression] = STATE(40),
    [sym_compound_expression] = STATE(40),
    [sym_simple_expression] = STATE(40),
    [sym__bool_lhs] = STATE(40),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(40),
    [sym_group] = STATE(40),
    [sym_boolean] = STATE(40),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(40),
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
    [sym__expression] = STATE(95),
    [sym_not_expression] = STATE(95),
    [sym_in_expression] = STATE(95),
    [sym_compound_expression] = STATE(95),
    [sym_simple_expression] = STATE(95),
    [sym__bool_lhs] = STATE(95),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(95),
    [sym_group] = STATE(95),
    [sym_boolean] = STATE(95),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(95),
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
    [sym__expression] = STATE(24),
    [sym_not_expression] = STATE(24),
    [sym_in_expression] = STATE(24),
    [sym_compound_expression] = STATE(24),
    [sym_simple_expression] = STATE(24),
    [sym__bool_lhs] = STATE(24),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(24),
    [sym_group] = STATE(24),
    [sym_boolean] = STATE(24),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(24),
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
    [sym__expression] = STATE(39),
    [sym_not_expression] = STATE(39),
    [sym_in_expression] = STATE(39),
    [sym_compound_expression] = STATE(39),
    [sym_simple_expression] = STATE(39),
    [sym__bool_lhs] = STATE(39),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(39),
    [sym_group] = STATE(39),
    [sym_boolean] = STATE(39),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(39),
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
    [sym__expression] = STATE(19),
    [sym_not_expression] = STATE(19),
    [sym_in_expression] = STATE(19),
    [sym_compound_expression] = STATE(19),
    [sym_simple_expression] = STATE(19),
    [sym__bool_lhs] = STATE(19),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(19),
    [sym_group] = STATE(19),
    [sym_boolean] = STATE(19),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(19),
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
    [sym__expression] = STATE(32),
    [sym_not_expression] = STATE(32),
    [sym_in_expression] = STATE(32),
    [sym_compound_expression] = STATE(32),
    [sym_simple_expression] = STATE(32),
    [sym__bool_lhs] = STATE(32),
    [sym__number_lhs] = STATE(92),
    [sym__string_lhs] = STATE(85),
    [sym_string_func] = STATE(85),
    [sym_number_func] = STATE(92),
    [sym_bool_func] = STATE(32),
    [sym_group] = STATE(32),
    [sym_boolean] = STATE(32),
    [sym_not_operator] = STATE(8),
    [sym__array_lhs] = STATE(195),
    [sym__stringlike_field] = STATE(83),
    [sym_number_field] = STATE(92),
    [sym_ip_field] = STATE(98),
    [sym_string_field] = STATE(83),
    [sym_map_string_array_field] = STATE(194),
    [sym_array_string_field] = STATE(195),
    [sym_bool_field] = STATE(32),
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
  [10] = {
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
  [11] = {
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
  [12] = {
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
  [13] = {
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
  [14] = {
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
  [15] = {
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
  [16] = {
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
  [17] = {
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
  [20] = {
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
  [21] = {
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
  [22] = {
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
  [23] = {
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
  [24] = {
    [ts_builtin_sym_end] = ACTIONS(147),
    [anon_sym_AMP_AMP] = ACTIONS(159),
    [anon_sym_and] = ACTIONS(159),
    [anon_sym_xor] = ACTIONS(161),
    [anon_sym_CARET_CARET] = ACTIONS(161),
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
  [25] = {
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
  [26] = {
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
  [27] = {
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
  [28] = {
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
  [29] = {
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
  [30] = {
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
  [31] = {
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
  [32] = {
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
  [33] = {
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
  [34] = {
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
  [35] = {
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
  [36] = {
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
  [37] = {
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
  [38] = {
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
  [39] = {
    [ts_builtin_sym_end] = ACTIONS(147),
    [anon_sym_AMP_AMP] = ACTIONS(159),
    [anon_sym_and] = ACTIONS(159),
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
  [40] = {
    [ts_builtin_sym_end] = ACTIONS(187),
    [anon_sym_AMP_AMP] = ACTIONS(159),
    [anon_sym_and] = ACTIONS(159),
    [anon_sym_xor] = ACTIONS(161),
    [anon_sym_CARET_CARET] = ACTIONS(161),
    [anon_sym_or] = ACTIONS(189),
    [anon_sym_PIPE_PIPE] = ACTIONS(189),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(187),
    [anon_sym_LPAREN] = ACTIONS(187),
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
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(191),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(191),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(191),
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
  [41] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(193),
    [anon_sym_LPAREN] = ACTIONS(193),
    [anon_sym_lookup_json_string] = ACTIONS(193),
    [anon_sym_lower] = ACTIONS(193),
    [anon_sym_regex_replace] = ACTIONS(193),
    [anon_sym_remove_bytes] = ACTIONS(193),
    [anon_sym_to_string] = ACTIONS(193),
    [anon_sym_upper] = ACTIONS(193),
    [anon_sym_url_decode] = ACTIONS(193),
    [anon_sym_uuidv4] = ACTIONS(193),
    [anon_sym_len] = ACTIONS(193),
    [anon_sym_ends_with] = ACTIONS(193),
    [anon_sym_starts_with] = ACTIONS(193),
    [anon_sym_true] = ACTIONS(193),
    [anon_sym_false] = ACTIONS(193),
    [anon_sym_not] = ACTIONS(193),
    [anon_sym_BANG] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(193),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(193),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(193),
    [anon_sym_ip_DOTsrc] = ACTIONS(195),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(193),
    [anon_sym_http_DOTcookie] = ACTIONS(193),
    [anon_sym_http_DOThost] = ACTIONS(193),
    [anon_sym_http_DOTreferer] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(193),
    [anon_sym_http_DOTuser_agent] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(193),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(193),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(193),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(193),
    [anon_sym_ssl] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(193),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(193),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(193),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(193),
  },
  [42] = {
    [anon_sym_in] = ACTIONS(197),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(197),
    [anon_sym_ne] = ACTIONS(197),
    [anon_sym_lt] = ACTIONS(197),
    [anon_sym_le] = ACTIONS(199),
    [anon_sym_gt] = ACTIONS(197),
    [anon_sym_ge] = ACTIONS(197),
    [anon_sym_EQ_EQ] = ACTIONS(197),
    [anon_sym_BANG_EQ] = ACTIONS(197),
    [anon_sym_LT] = ACTIONS(199),
    [anon_sym_LT_EQ] = ACTIONS(197),
    [anon_sym_GT] = ACTIONS(199),
    [anon_sym_GT_EQ] = ACTIONS(197),
    [anon_sym_contains] = ACTIONS(197),
    [anon_sym_matches] = ACTIONS(197),
    [anon_sym_TILDE] = ACTIONS(197),
    [anon_sym_concat] = ACTIONS(197),
    [anon_sym_COMMA] = ACTIONS(197),
    [anon_sym_RPAREN] = ACTIONS(197),
    [anon_sym_lookup_json_string] = ACTIONS(197),
    [anon_sym_lower] = ACTIONS(197),
    [anon_sym_regex_replace] = ACTIONS(197),
    [anon_sym_remove_bytes] = ACTIONS(197),
    [anon_sym_to_string] = ACTIONS(197),
    [anon_sym_upper] = ACTIONS(197),
    [anon_sym_url_decode] = ACTIONS(197),
    [anon_sym_uuidv4] = ACTIONS(197),
    [anon_sym_len] = ACTIONS(197),
    [anon_sym_ends_with] = ACTIONS(197),
    [anon_sym_starts_with] = ACTIONS(197),
    [sym_number] = ACTIONS(197),
    [sym_string] = ACTIONS(197),
    [anon_sym_http_DOTcookie] = ACTIONS(197),
    [anon_sym_http_DOThost] = ACTIONS(197),
    [anon_sym_http_DOTreferer] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(197),
    [anon_sym_http_DOTuser_agent] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(197),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(197),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(197),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(197),
  },
  [43] = {
    [anon_sym_in] = ACTIONS(201),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(201),
    [anon_sym_ne] = ACTIONS(201),
    [anon_sym_lt] = ACTIONS(201),
    [anon_sym_le] = ACTIONS(203),
    [anon_sym_gt] = ACTIONS(201),
    [anon_sym_ge] = ACTIONS(201),
    [anon_sym_EQ_EQ] = ACTIONS(201),
    [anon_sym_BANG_EQ] = ACTIONS(201),
    [anon_sym_LT] = ACTIONS(203),
    [anon_sym_LT_EQ] = ACTIONS(201),
    [anon_sym_GT] = ACTIONS(203),
    [anon_sym_GT_EQ] = ACTIONS(201),
    [anon_sym_contains] = ACTIONS(201),
    [anon_sym_matches] = ACTIONS(201),
    [anon_sym_TILDE] = ACTIONS(201),
    [anon_sym_concat] = ACTIONS(201),
    [anon_sym_COMMA] = ACTIONS(201),
    [anon_sym_RPAREN] = ACTIONS(201),
    [anon_sym_lookup_json_string] = ACTIONS(201),
    [anon_sym_lower] = ACTIONS(201),
    [anon_sym_regex_replace] = ACTIONS(201),
    [anon_sym_remove_bytes] = ACTIONS(201),
    [anon_sym_to_string] = ACTIONS(201),
    [anon_sym_upper] = ACTIONS(201),
    [anon_sym_url_decode] = ACTIONS(201),
    [anon_sym_uuidv4] = ACTIONS(201),
    [anon_sym_len] = ACTIONS(201),
    [anon_sym_ends_with] = ACTIONS(201),
    [anon_sym_starts_with] = ACTIONS(201),
    [sym_number] = ACTIONS(201),
    [sym_string] = ACTIONS(201),
    [anon_sym_http_DOTcookie] = ACTIONS(201),
    [anon_sym_http_DOThost] = ACTIONS(201),
    [anon_sym_http_DOTreferer] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(201),
    [anon_sym_http_DOTuser_agent] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(201),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(201),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(201),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(201),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    ACTIONS(219), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(166), 1,
      sym_array_field_expansion,
    STATE(206), 1,
      sym_bytes_field,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(207), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [92] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(223), 1,
      anon_sym_concat,
    ACTIONS(226), 1,
      anon_sym_RPAREN,
    ACTIONS(228), 1,
      anon_sym_lookup_json_string,
    ACTIONS(234), 1,
      anon_sym_regex_replace,
    ACTIONS(237), 1,
      anon_sym_remove_bytes,
    ACTIONS(240), 1,
      anon_sym_uuidv4,
    ACTIONS(246), 1,
      sym_string,
    ACTIONS(255), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(258), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    STATE(45), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(243), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    ACTIONS(252), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(261), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(231), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
    ACTIONS(249), 25,
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
  [184] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    ACTIONS(219), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(178), 1,
      sym_array_field_expansion,
    STATE(181), 1,
      sym_bytes_field,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(168), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [276] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(266), 1,
      anon_sym_RPAREN,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    STATE(45), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [368] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    ACTIONS(282), 1,
      anon_sym_RPAREN,
    STATE(45), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [460] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    ACTIONS(284), 1,
      anon_sym_RPAREN,
    STATE(45), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [552] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    ACTIONS(286), 1,
      anon_sym_RPAREN,
    STATE(45), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [644] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    ACTIONS(288), 1,
      sym_string,
    STATE(136), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(189), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [733] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    STATE(47), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [822] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    STATE(50), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [911] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    STATE(49), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1000] = 18,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(264), 1,
      anon_sym_concat,
    ACTIONS(268), 1,
      anon_sym_lookup_json_string,
    ACTIONS(272), 1,
      anon_sym_regex_replace,
    ACTIONS(274), 1,
      anon_sym_remove_bytes,
    ACTIONS(276), 1,
      anon_sym_uuidv4,
    ACTIONS(280), 1,
      sym_string,
    STATE(48), 1,
      aux_sym_string_func_repeat1,
    STATE(194), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(278), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(61), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(195), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(47), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(270), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1089] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(109), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(110), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1175] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(205), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(204), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1261] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(210), 1,
      sym_array_field_expansion,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(208), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1347] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(166), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(224), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1433] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(217), 1,
      sym_array_field_expansion,
    ACTIONS(41), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(133), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(198), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1519] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(292), 1,
      anon_sym_COMMA,
    ACTIONS(294), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(290), 43,
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
      anon_sym_len,
      anon_sym_ends_with,
      anon_sym_starts_with,
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
  [1576] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(298), 1,
      anon_sym_COMMA,
    ACTIONS(300), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(296), 43,
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
      anon_sym_len,
      anon_sym_ends_with,
      anon_sym_starts_with,
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
  [1633] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(304), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(302), 43,
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
      anon_sym_len,
      anon_sym_ends_with,
      anon_sym_starts_with,
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
  [1687] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(308), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(306), 43,
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
      anon_sym_len,
      anon_sym_ends_with,
      anon_sym_starts_with,
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
  [1741] = 19,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(33), 1,
      anon_sym_cf_DOTwaf_DOTscore,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(166), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(37), 2,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    STATE(211), 3,
      sym_number_field,
      sym_ip_field,
      sym_bool_field,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
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
  [1825] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(111), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [1876] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(217), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [1927] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(205), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [1978] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(178), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2029] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(233), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2080] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(213), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2131] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(232), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2182] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(242), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2233] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(212), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2284] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(136), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2335] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(231), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2386] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(109), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2437] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(209), 1,
      sym_map_string_array_field,
    STATE(210), 1,
      sym_array_field_expansion,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2488] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(43), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(205), 1,
      anon_sym_concat,
    ACTIONS(207), 1,
      anon_sym_lookup_json_string,
    ACTIONS(211), 1,
      anon_sym_regex_replace,
    ACTIONS(213), 1,
      anon_sym_remove_bytes,
    ACTIONS(215), 1,
      anon_sym_uuidv4,
    STATE(166), 1,
      sym_array_field_expansion,
    STATE(209), 1,
      sym_map_string_array_field,
    ACTIONS(217), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(174), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(221), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(209), 5,
      anon_sym_lower,
      anon_sym_to_string,
      anon_sym_upper,
      anon_sym_url_decode,
      anon_sym_len,
  [2539] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(312), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(310), 14,
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
  [2563] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(316), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(314), 14,
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
  [2587] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(320), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(318), 14,
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
  [2611] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(324), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(322), 14,
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
  [2635] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(328), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(326), 14,
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
  [2659] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(330), 1,
      anon_sym_in,
    ACTIONS(332), 1,
      anon_sym_eq,
    ACTIONS(334), 1,
      anon_sym_ne,
    ACTIONS(336), 1,
      anon_sym_lt,
    ACTIONS(338), 1,
      anon_sym_le,
    ACTIONS(340), 1,
      anon_sym_gt,
    ACTIONS(342), 1,
      anon_sym_ge,
    ACTIONS(344), 1,
      anon_sym_EQ_EQ,
    ACTIONS(346), 1,
      anon_sym_BANG_EQ,
    ACTIONS(348), 1,
      anon_sym_LT,
    ACTIONS(350), 1,
      anon_sym_LT_EQ,
    ACTIONS(352), 1,
      anon_sym_GT,
    ACTIONS(354), 1,
      anon_sym_GT_EQ,
    ACTIONS(356), 1,
      anon_sym_contains,
    ACTIONS(358), 1,
      anon_sym_matches,
    ACTIONS(360), 1,
      anon_sym_TILDE,
  [2711] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(364), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(362), 14,
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
  [2735] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(368), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(366), 14,
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
  [2759] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(372), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(370), 14,
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
  [2783] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(376), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(374), 14,
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
  [2807] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(380), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(378), 14,
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
  [2831] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(384), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(382), 12,
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
  [2853] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(386), 1,
      anon_sym_in,
    ACTIONS(390), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(388), 10,
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
  [2876] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(394), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(392), 11,
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
  [2897] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(398), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(396), 11,
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
  [2918] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(400), 1,
      anon_sym_RPAREN,
    ACTIONS(159), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(161), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(189), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [2937] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(402), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [2949] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(404), 1,
      anon_sym_RBRACE,
    ACTIONS(406), 1,
      sym_ipv4,
    STATE(97), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [2964] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 1,
      anon_sym_in,
    ACTIONS(411), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [2977] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(413), 1,
      anon_sym_RBRACE,
    ACTIONS(415), 1,
      sym_ipv4,
    STATE(97), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [2992] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(415), 1,
      sym_ipv4,
    STATE(99), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [3004] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(417), 1,
      anon_sym_RPAREN,
    STATE(103), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(419), 2,
      sym_number,
      sym_string,
  [3018] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(421), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3028] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(423), 1,
      anon_sym_RPAREN,
    STATE(103), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(425), 2,
      sym_number,
      sym_string,
  [3042] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(428), 1,
      anon_sym_COMMA,
    ACTIONS(430), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3054] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(432), 1,
      anon_sym_RPAREN,
    STATE(103), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(419), 2,
      sym_number,
      sym_string,
  [3068] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(434), 1,
      anon_sym_RPAREN,
    STATE(103), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(419), 2,
      sym_number,
      sym_string,
  [3082] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(436), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3092] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(415), 1,
      sym_ipv4,
    STATE(37), 2,
      sym__ip,
      sym_ip_range,
  [3103] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(105), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(419), 2,
      sym_number,
      sym_string,
  [3114] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(106), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(419), 2,
      sym_number,
      sym_string,
  [3125] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(101), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(419), 2,
      sym_number,
      sym_string,
  [3136] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(438), 1,
      anon_sym_RBRACE,
    ACTIONS(440), 1,
      sym_string,
    STATE(112), 1,
      aux_sym_string_set_repeat1,
  [3149] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(443), 1,
      anon_sym_RBRACE,
    ACTIONS(445), 1,
      sym_number,
    STATE(113), 1,
      aux_sym_number_set_repeat1,
  [3162] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(423), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [3171] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(448), 1,
      anon_sym_LBRACE,
    ACTIONS(450), 1,
      sym_ip_list,
    STATE(11), 1,
      sym_ip_set,
  [3184] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(452), 1,
      anon_sym_RBRACE,
    ACTIONS(454), 1,
      sym_string,
    STATE(112), 1,
      aux_sym_string_set_repeat1,
  [3197] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(456), 1,
      anon_sym_RBRACE,
    ACTIONS(458), 1,
      sym_number,
    STATE(113), 1,
      aux_sym_number_set_repeat1,
  [3210] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(460), 1,
      anon_sym_LBRACK,
    ACTIONS(462), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3220] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(464), 1,
      sym_string,
    ACTIONS(466), 1,
      anon_sym_STAR,
  [3230] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(468), 1,
      anon_sym_LBRACK,
    ACTIONS(470), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3240] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(472), 1,
      anon_sym_LBRACK,
    ACTIONS(474), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3250] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(476), 1,
      anon_sym_LBRACK,
    ACTIONS(478), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3260] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      anon_sym_LBRACK,
    ACTIONS(482), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3270] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(484), 1,
      anon_sym_LBRACK,
    ACTIONS(486), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3280] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      anon_sym_LBRACK,
    ACTIONS(490), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3290] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(492), 1,
      anon_sym_LBRACK,
    ACTIONS(494), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3300] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(496), 1,
      anon_sym_LBRACK,
    ACTIONS(498), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3310] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(500), 1,
      sym_number,
    STATE(117), 1,
      aux_sym_number_set_repeat1,
  [3320] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(502), 1,
      sym_string,
    STATE(116), 1,
      aux_sym_string_set_repeat1,
  [3330] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(504), 1,
      anon_sym_LBRACE,
    STATE(11), 1,
      sym_number_set,
  [3340] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(506), 1,
      anon_sym_LBRACE,
    STATE(30), 1,
      sym_string_set,
  [3350] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(508), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [3358] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK,
    ACTIONS(512), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3368] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_RBRACK,
  [3375] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(516), 1,
      anon_sym_LPAREN,
  [3382] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(518), 1,
      anon_sym_COMMA,
  [3389] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 1,
      sym_string,
  [3396] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(522), 1,
      anon_sym_LPAREN,
  [3403] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LPAREN,
  [3410] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(526), 1,
      anon_sym_LPAREN,
  [3417] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      anon_sym_LPAREN,
  [3424] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(530), 1,
      anon_sym_LPAREN,
  [3431] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(532), 1,
      anon_sym_LPAREN,
  [3438] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      anon_sym_LBRACK,
  [3445] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(534), 1,
      anon_sym_LPAREN,
  [3452] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(536), 1,
      sym_string,
  [3459] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      sym_string,
  [3466] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(540), 1,
      sym_string,
  [3473] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      sym_string,
  [3480] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(544), 1,
      sym_string,
  [3487] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(546), 1,
      sym_string,
  [3494] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(490), 1,
      anon_sym_LBRACK,
  [3501] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(548), 1,
      sym_number,
  [3508] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(550), 1,
      sym_string,
  [3515] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(552), 1,
      sym_string,
  [3522] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(554), 1,
      sym_string,
  [3529] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(556), 1,
      sym_string,
  [3536] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      aux_sym_ip_range_token1,
  [3543] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(486), 1,
      anon_sym_LBRACK,
  [3550] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(560), 1,
      sym_string,
  [3557] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      sym_string,
  [3564] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(564), 1,
      sym_string,
  [3571] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      sym_string,
  [3578] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(568), 1,
      sym_string,
  [3585] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_RBRACK,
  [3592] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(572), 1,
      anon_sym_RPAREN,
  [3599] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(482), 1,
      anon_sym_LBRACK,
  [3606] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(574), 1,
      anon_sym_COMMA,
  [3613] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(576), 1,
      sym_string,
  [3620] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(578), 1,
      anon_sym_COMMA,
  [3627] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(580), 1,
      anon_sym_COMMA,
  [3634] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(582), 1,
      anon_sym_RPAREN,
  [3641] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(584), 1,
      anon_sym_RPAREN,
  [3648] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(512), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3655] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(586), 1,
      anon_sym_RPAREN,
  [3662] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(588), 1,
      anon_sym_RPAREN,
  [3669] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(590), 1,
      sym_string,
  [3676] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(592), 1,
      anon_sym_COMMA,
  [3683] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(594), 1,
      sym_string,
  [3690] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(596), 1,
      anon_sym_RPAREN,
  [3697] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(598), 1,
      anon_sym_COMMA,
  [3704] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(600), 1,
      anon_sym_COMMA,
  [3711] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      sym_string,
  [3718] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(604), 1,
      sym_string,
  [3725] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      sym_string,
  [3732] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(608), 1,
      anon_sym_RBRACK,
  [3739] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(610), 1,
      sym_number,
  [3746] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(478), 1,
      anon_sym_LBRACK,
  [3753] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(612), 1,
      anon_sym_COMMA,
  [3760] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(614), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [3767] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(616), 1,
      sym_string,
  [3774] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(618), 1,
      sym_string,
  [3781] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      anon_sym_LBRACK,
  [3788] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(620), 1,
      anon_sym_LBRACK,
  [3795] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(622), 1,
      anon_sym_LBRACK,
  [3802] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(474), 1,
      anon_sym_LBRACK,
  [3809] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(624), 1,
      ts_builtin_sym_end,
  [3816] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(626), 1,
      anon_sym_COMMA,
  [3823] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(628), 1,
      anon_sym_RPAREN,
  [3830] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(630), 1,
      anon_sym_RPAREN,
  [3837] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(470), 1,
      anon_sym_LBRACK,
  [3844] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(498), 1,
      anon_sym_LBRACK,
  [3851] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(632), 1,
      anon_sym_RBRACK,
  [3858] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(634), 1,
      anon_sym_COMMA,
  [3865] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(636), 1,
      anon_sym_COMMA,
  [3872] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(638), 1,
      anon_sym_RPAREN,
  [3879] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(640), 1,
      anon_sym_RPAREN,
  [3886] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(642), 1,
      anon_sym_RPAREN,
  [3893] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(644), 1,
      anon_sym_LBRACK,
  [3900] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(646), 1,
      anon_sym_RPAREN,
  [3907] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(648), 1,
      anon_sym_RPAREN,
  [3914] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(650), 1,
      anon_sym_RPAREN,
  [3921] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(652), 1,
      anon_sym_RPAREN,
  [3928] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(654), 1,
      sym_string,
  [3935] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(656), 1,
      anon_sym_LBRACK,
  [3942] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(658), 1,
      anon_sym_LPAREN,
  [3949] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(660), 1,
      anon_sym_COMMA,
  [3956] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(662), 1,
      anon_sym_LPAREN,
  [3963] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(664), 1,
      anon_sym_RPAREN,
  [3970] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(666), 1,
      anon_sym_RPAREN,
  [3977] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(668), 1,
      anon_sym_RPAREN,
  [3984] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(670), 1,
      anon_sym_LPAREN,
  [3991] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(672), 1,
      anon_sym_LPAREN,
  [3998] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(674), 1,
      anon_sym_RPAREN,
  [4005] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(676), 1,
      anon_sym_LPAREN,
  [4012] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(678), 1,
      anon_sym_LPAREN,
  [4019] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(680), 1,
      sym_string,
  [4026] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(682), 1,
      sym_string,
  [4033] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(684), 1,
      sym_string,
  [4040] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(686), 1,
      anon_sym_LPAREN,
  [4047] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(688), 1,
      anon_sym_COMMA,
  [4054] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(690), 1,
      anon_sym_COMMA,
  [4061] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(692), 1,
      anon_sym_COMMA,
  [4068] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(694), 1,
      anon_sym_LPAREN,
  [4075] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(696), 1,
      anon_sym_LPAREN,
  [4082] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(698), 1,
      anon_sym_LPAREN,
  [4089] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(700), 1,
      anon_sym_COMMA,
  [4096] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(702), 1,
      anon_sym_LPAREN,
  [4103] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(704), 1,
      anon_sym_LPAREN,
  [4110] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(706), 1,
      anon_sym_LPAREN,
  [4117] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(708), 1,
      sym_string,
  [4124] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(710), 1,
      anon_sym_COMMA,
  [4131] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(712), 1,
      anon_sym_LPAREN,
  [4138] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(714), 1,
      anon_sym_LPAREN,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(44)] = 0,
  [SMALL_STATE(45)] = 92,
  [SMALL_STATE(46)] = 184,
  [SMALL_STATE(47)] = 276,
  [SMALL_STATE(48)] = 368,
  [SMALL_STATE(49)] = 460,
  [SMALL_STATE(50)] = 552,
  [SMALL_STATE(51)] = 644,
  [SMALL_STATE(52)] = 733,
  [SMALL_STATE(53)] = 822,
  [SMALL_STATE(54)] = 911,
  [SMALL_STATE(55)] = 1000,
  [SMALL_STATE(56)] = 1089,
  [SMALL_STATE(57)] = 1175,
  [SMALL_STATE(58)] = 1261,
  [SMALL_STATE(59)] = 1347,
  [SMALL_STATE(60)] = 1433,
  [SMALL_STATE(61)] = 1519,
  [SMALL_STATE(62)] = 1576,
  [SMALL_STATE(63)] = 1633,
  [SMALL_STATE(64)] = 1687,
  [SMALL_STATE(65)] = 1741,
  [SMALL_STATE(66)] = 1825,
  [SMALL_STATE(67)] = 1876,
  [SMALL_STATE(68)] = 1927,
  [SMALL_STATE(69)] = 1978,
  [SMALL_STATE(70)] = 2029,
  [SMALL_STATE(71)] = 2080,
  [SMALL_STATE(72)] = 2131,
  [SMALL_STATE(73)] = 2182,
  [SMALL_STATE(74)] = 2233,
  [SMALL_STATE(75)] = 2284,
  [SMALL_STATE(76)] = 2335,
  [SMALL_STATE(77)] = 2386,
  [SMALL_STATE(78)] = 2437,
  [SMALL_STATE(79)] = 2488,
  [SMALL_STATE(80)] = 2539,
  [SMALL_STATE(81)] = 2563,
  [SMALL_STATE(82)] = 2587,
  [SMALL_STATE(83)] = 2611,
  [SMALL_STATE(84)] = 2635,
  [SMALL_STATE(85)] = 2659,
  [SMALL_STATE(86)] = 2711,
  [SMALL_STATE(87)] = 2735,
  [SMALL_STATE(88)] = 2759,
  [SMALL_STATE(89)] = 2783,
  [SMALL_STATE(90)] = 2807,
  [SMALL_STATE(91)] = 2831,
  [SMALL_STATE(92)] = 2853,
  [SMALL_STATE(93)] = 2876,
  [SMALL_STATE(94)] = 2897,
  [SMALL_STATE(95)] = 2918,
  [SMALL_STATE(96)] = 2937,
  [SMALL_STATE(97)] = 2949,
  [SMALL_STATE(98)] = 2964,
  [SMALL_STATE(99)] = 2977,
  [SMALL_STATE(100)] = 2992,
  [SMALL_STATE(101)] = 3004,
  [SMALL_STATE(102)] = 3018,
  [SMALL_STATE(103)] = 3028,
  [SMALL_STATE(104)] = 3042,
  [SMALL_STATE(105)] = 3054,
  [SMALL_STATE(106)] = 3068,
  [SMALL_STATE(107)] = 3082,
  [SMALL_STATE(108)] = 3092,
  [SMALL_STATE(109)] = 3103,
  [SMALL_STATE(110)] = 3114,
  [SMALL_STATE(111)] = 3125,
  [SMALL_STATE(112)] = 3136,
  [SMALL_STATE(113)] = 3149,
  [SMALL_STATE(114)] = 3162,
  [SMALL_STATE(115)] = 3171,
  [SMALL_STATE(116)] = 3184,
  [SMALL_STATE(117)] = 3197,
  [SMALL_STATE(118)] = 3210,
  [SMALL_STATE(119)] = 3220,
  [SMALL_STATE(120)] = 3230,
  [SMALL_STATE(121)] = 3240,
  [SMALL_STATE(122)] = 3250,
  [SMALL_STATE(123)] = 3260,
  [SMALL_STATE(124)] = 3270,
  [SMALL_STATE(125)] = 3280,
  [SMALL_STATE(126)] = 3290,
  [SMALL_STATE(127)] = 3300,
  [SMALL_STATE(128)] = 3310,
  [SMALL_STATE(129)] = 3320,
  [SMALL_STATE(130)] = 3330,
  [SMALL_STATE(131)] = 3340,
  [SMALL_STATE(132)] = 3350,
  [SMALL_STATE(133)] = 3358,
  [SMALL_STATE(134)] = 3368,
  [SMALL_STATE(135)] = 3375,
  [SMALL_STATE(136)] = 3382,
  [SMALL_STATE(137)] = 3389,
  [SMALL_STATE(138)] = 3396,
  [SMALL_STATE(139)] = 3403,
  [SMALL_STATE(140)] = 3410,
  [SMALL_STATE(141)] = 3417,
  [SMALL_STATE(142)] = 3424,
  [SMALL_STATE(143)] = 3431,
  [SMALL_STATE(144)] = 3438,
  [SMALL_STATE(145)] = 3445,
  [SMALL_STATE(146)] = 3452,
  [SMALL_STATE(147)] = 3459,
  [SMALL_STATE(148)] = 3466,
  [SMALL_STATE(149)] = 3473,
  [SMALL_STATE(150)] = 3480,
  [SMALL_STATE(151)] = 3487,
  [SMALL_STATE(152)] = 3494,
  [SMALL_STATE(153)] = 3501,
  [SMALL_STATE(154)] = 3508,
  [SMALL_STATE(155)] = 3515,
  [SMALL_STATE(156)] = 3522,
  [SMALL_STATE(157)] = 3529,
  [SMALL_STATE(158)] = 3536,
  [SMALL_STATE(159)] = 3543,
  [SMALL_STATE(160)] = 3550,
  [SMALL_STATE(161)] = 3557,
  [SMALL_STATE(162)] = 3564,
  [SMALL_STATE(163)] = 3571,
  [SMALL_STATE(164)] = 3578,
  [SMALL_STATE(165)] = 3585,
  [SMALL_STATE(166)] = 3592,
  [SMALL_STATE(167)] = 3599,
  [SMALL_STATE(168)] = 3606,
  [SMALL_STATE(169)] = 3613,
  [SMALL_STATE(170)] = 3620,
  [SMALL_STATE(171)] = 3627,
  [SMALL_STATE(172)] = 3634,
  [SMALL_STATE(173)] = 3641,
  [SMALL_STATE(174)] = 3648,
  [SMALL_STATE(175)] = 3655,
  [SMALL_STATE(176)] = 3662,
  [SMALL_STATE(177)] = 3669,
  [SMALL_STATE(178)] = 3676,
  [SMALL_STATE(179)] = 3683,
  [SMALL_STATE(180)] = 3690,
  [SMALL_STATE(181)] = 3697,
  [SMALL_STATE(182)] = 3704,
  [SMALL_STATE(183)] = 3711,
  [SMALL_STATE(184)] = 3718,
  [SMALL_STATE(185)] = 3725,
  [SMALL_STATE(186)] = 3732,
  [SMALL_STATE(187)] = 3739,
  [SMALL_STATE(188)] = 3746,
  [SMALL_STATE(189)] = 3753,
  [SMALL_STATE(190)] = 3760,
  [SMALL_STATE(191)] = 3767,
  [SMALL_STATE(192)] = 3774,
  [SMALL_STATE(193)] = 3781,
  [SMALL_STATE(194)] = 3788,
  [SMALL_STATE(195)] = 3795,
  [SMALL_STATE(196)] = 3802,
  [SMALL_STATE(197)] = 3809,
  [SMALL_STATE(198)] = 3816,
  [SMALL_STATE(199)] = 3823,
  [SMALL_STATE(200)] = 3830,
  [SMALL_STATE(201)] = 3837,
  [SMALL_STATE(202)] = 3844,
  [SMALL_STATE(203)] = 3851,
  [SMALL_STATE(204)] = 3858,
  [SMALL_STATE(205)] = 3865,
  [SMALL_STATE(206)] = 3872,
  [SMALL_STATE(207)] = 3879,
  [SMALL_STATE(208)] = 3886,
  [SMALL_STATE(209)] = 3893,
  [SMALL_STATE(210)] = 3900,
  [SMALL_STATE(211)] = 3907,
  [SMALL_STATE(212)] = 3914,
  [SMALL_STATE(213)] = 3921,
  [SMALL_STATE(214)] = 3928,
  [SMALL_STATE(215)] = 3935,
  [SMALL_STATE(216)] = 3942,
  [SMALL_STATE(217)] = 3949,
  [SMALL_STATE(218)] = 3956,
  [SMALL_STATE(219)] = 3963,
  [SMALL_STATE(220)] = 3970,
  [SMALL_STATE(221)] = 3977,
  [SMALL_STATE(222)] = 3984,
  [SMALL_STATE(223)] = 3991,
  [SMALL_STATE(224)] = 3998,
  [SMALL_STATE(225)] = 4005,
  [SMALL_STATE(226)] = 4012,
  [SMALL_STATE(227)] = 4019,
  [SMALL_STATE(228)] = 4026,
  [SMALL_STATE(229)] = 4033,
  [SMALL_STATE(230)] = 4040,
  [SMALL_STATE(231)] = 4047,
  [SMALL_STATE(232)] = 4054,
  [SMALL_STATE(233)] = 4061,
  [SMALL_STATE(234)] = 4068,
  [SMALL_STATE(235)] = 4075,
  [SMALL_STATE(236)] = 4082,
  [SMALL_STATE(237)] = 4089,
  [SMALL_STATE(238)] = 4096,
  [SMALL_STATE(239)] = 4103,
  [SMALL_STATE(240)] = 4110,
  [SMALL_STATE(241)] = 4117,
  [SMALL_STATE(242)] = 4124,
  [SMALL_STATE(243)] = 4131,
  [SMALL_STATE(244)] = 4138,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(135),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(4),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(243),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(236),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(235),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(234),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(226),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(225),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(218),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(216),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(91),
  [33] = {.entry = {.count = 1, .reusable = false}}, SHIFT(91),
  [35] = {.entry = {.count = 1, .reusable = false}}, SHIFT(96),
  [37] = {.entry = {.count = 1, .reusable = true}}, SHIFT(96),
  [39] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [41] = {.entry = {.count = 1, .reusable = false}}, SHIFT(42),
  [43] = {.entry = {.count = 1, .reusable = true}}, SHIFT(215),
  [45] = {.entry = {.count = 1, .reusable = false}}, SHIFT(215),
  [47] = {.entry = {.count = 1, .reusable = true}}, SHIFT(202),
  [49] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [51] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [53] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(135),
  [56] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(4),
  [59] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(243),
  [62] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(236),
  [65] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(235),
  [68] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(234),
  [71] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(226),
  [74] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(225),
  [77] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(218),
  [80] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(216),
  [83] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(15),
  [86] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(41),
  [89] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(91),
  [92] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(91),
  [95] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(96),
  [98] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(96),
  [101] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(42),
  [104] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(42),
  [107] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(215),
  [110] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(215),
  [113] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(202),
  [116] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(22),
  [119] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [121] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [123] = {.entry = {.count = 1, .reusable = true}}, SHIFT(158),
  [125] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [127] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [129] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 3),
  [133] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 3),
  [135] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [137] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [139] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 4),
  [141] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 4),
  [143] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [145] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [147] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 3),
  [149] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 3),
  [151] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 6, .production_id = 20),
  [153] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 6, .production_id = 20),
  [155] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_field, 1),
  [157] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_field, 1),
  [159] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [161] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [163] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 4),
  [165] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 4),
  [167] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [169] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [171] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [173] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [175] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [177] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [179] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3, .production_id = 2),
  [181] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3, .production_id = 2),
  [183] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 3),
  [185] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 3),
  [187] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [189] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [191] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [193] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [195] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [197] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [199] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [201] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__stringlike_field, 4, .production_id = 9),
  [203] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__stringlike_field, 4, .production_id = 9),
  [205] = {.entry = {.count = 1, .reusable = true}}, SHIFT(145),
  [207] = {.entry = {.count = 1, .reusable = true}}, SHIFT(143),
  [209] = {.entry = {.count = 1, .reusable = true}}, SHIFT(142),
  [211] = {.entry = {.count = 1, .reusable = true}}, SHIFT(141),
  [213] = {.entry = {.count = 1, .reusable = true}}, SHIFT(140),
  [215] = {.entry = {.count = 1, .reusable = true}}, SHIFT(139),
  [217] = {.entry = {.count = 1, .reusable = true}}, SHIFT(138),
  [219] = {.entry = {.count = 1, .reusable = true}}, SHIFT(132),
  [221] = {.entry = {.count = 1, .reusable = true}}, SHIFT(127),
  [223] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(238),
  [226] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15),
  [228] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(230),
  [231] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(222),
  [234] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(244),
  [237] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(239),
  [240] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(223),
  [243] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(240),
  [246] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(62),
  [249] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(42),
  [252] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(42),
  [255] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(215),
  [258] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(215),
  [261] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(202),
  [264] = {.entry = {.count = 1, .reusable = true}}, SHIFT(238),
  [266] = {.entry = {.count = 1, .reusable = true}}, SHIFT(122),
  [268] = {.entry = {.count = 1, .reusable = true}}, SHIFT(230),
  [270] = {.entry = {.count = 1, .reusable = true}}, SHIFT(222),
  [272] = {.entry = {.count = 1, .reusable = true}}, SHIFT(244),
  [274] = {.entry = {.count = 1, .reusable = true}}, SHIFT(239),
  [276] = {.entry = {.count = 1, .reusable = true}}, SHIFT(223),
  [278] = {.entry = {.count = 1, .reusable = true}}, SHIFT(240),
  [280] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [282] = {.entry = {.count = 1, .reusable = true}}, SHIFT(82),
  [284] = {.entry = {.count = 1, .reusable = true}}, SHIFT(188),
  [286] = {.entry = {.count = 1, .reusable = true}}, SHIFT(81),
  [288] = {.entry = {.count = 1, .reusable = true}}, SHIFT(182),
  [290] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [292] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [294] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [296] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [298] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [300] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [302] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [304] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [306] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [308] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [310] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 8, .production_id = 22),
  [312] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 8, .production_id = 22),
  [314] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 14),
  [316] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 14),
  [318] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [320] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [322] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [324] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [326] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 18),
  [328] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 18),
  [330] = {.entry = {.count = 1, .reusable = true}}, SHIFT(131),
  [332] = {.entry = {.count = 1, .reusable = true}}, SHIFT(185),
  [334] = {.entry = {.count = 1, .reusable = true}}, SHIFT(184),
  [336] = {.entry = {.count = 1, .reusable = true}}, SHIFT(183),
  [338] = {.entry = {.count = 1, .reusable = true}}, SHIFT(137),
  [340] = {.entry = {.count = 1, .reusable = true}}, SHIFT(214),
  [342] = {.entry = {.count = 1, .reusable = true}}, SHIFT(179),
  [344] = {.entry = {.count = 1, .reusable = true}}, SHIFT(177),
  [346] = {.entry = {.count = 1, .reusable = true}}, SHIFT(169),
  [348] = {.entry = {.count = 1, .reusable = false}}, SHIFT(164),
  [350] = {.entry = {.count = 1, .reusable = true}}, SHIFT(163),
  [352] = {.entry = {.count = 1, .reusable = false}}, SHIFT(162),
  [354] = {.entry = {.count = 1, .reusable = true}}, SHIFT(161),
  [356] = {.entry = {.count = 1, .reusable = true}}, SHIFT(160),
  [358] = {.entry = {.count = 1, .reusable = true}}, SHIFT(157),
  [360] = {.entry = {.count = 1, .reusable = true}}, SHIFT(156),
  [362] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 17),
  [364] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 17),
  [366] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 5, .production_id = 12),
  [368] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 5, .production_id = 12),
  [370] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 6),
  [372] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 6),
  [374] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 5),
  [376] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 5),
  [378] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 8),
  [380] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 8),
  [382] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [384] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [386] = {.entry = {.count = 1, .reusable = true}}, SHIFT(130),
  [388] = {.entry = {.count = 1, .reusable = true}}, SHIFT(187),
  [390] = {.entry = {.count = 1, .reusable = false}}, SHIFT(187),
  [392] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 5),
  [394] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 5),
  [396] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 6),
  [398] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 6),
  [400] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [402] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [404] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [406] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(9),
  [409] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [411] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [413] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [415] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [417] = {.entry = {.count = 1, .reusable = true}}, SHIFT(123),
  [419] = {.entry = {.count = 1, .reusable = true}}, SHIFT(104),
  [421] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_field_expansion, 5, .production_id = 10),
  [423] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2),
  [425] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2), SHIFT_REPEAT(104),
  [428] = {.entry = {.count = 1, .reusable = true}}, SHIFT(114),
  [430] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 1),
  [432] = {.entry = {.count = 1, .reusable = true}}, SHIFT(167),
  [434] = {.entry = {.count = 1, .reusable = true}}, SHIFT(87),
  [436] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_field_expansion, 2, .production_id = 1),
  [438] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [440] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(112),
  [443] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [445] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(113),
  [448] = {.entry = {.count = 1, .reusable = true}}, SHIFT(100),
  [450] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [452] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [454] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [456] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [458] = {.entry = {.count = 1, .reusable = true}}, SHIFT(113),
  [460] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 6, .production_id = 17),
  [462] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 6, .production_id = 17),
  [464] = {.entry = {.count = 1, .reusable = true}}, SHIFT(134),
  [466] = {.entry = {.count = 1, .reusable = true}}, SHIFT(165),
  [468] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 8, .production_id = 21),
  [470] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 8, .production_id = 21),
  [472] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 6, .production_id = 19),
  [474] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 6, .production_id = 19),
  [476] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 6, .production_id = 14),
  [478] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 6, .production_id = 14),
  [480] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 5, .production_id = 11),
  [482] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 5, .production_id = 11),
  [484] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 4, .production_id = 10),
  [486] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 4, .production_id = 10),
  [488] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 4, .production_id = 7),
  [490] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 4, .production_id = 7),
  [492] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 4, .production_id = 5),
  [494] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 4, .production_id = 5),
  [496] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_string_field, 1),
  [498] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_string_field, 1),
  [500] = {.entry = {.count = 1, .reusable = true}}, SHIFT(117),
  [502] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [504] = {.entry = {.count = 1, .reusable = true}}, SHIFT(128),
  [506] = {.entry = {.count = 1, .reusable = true}}, SHIFT(129),
  [508] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [510] = {.entry = {.count = 1, .reusable = false}}, SHIFT(153),
  [512] = {.entry = {.count = 1, .reusable = true}}, SHIFT(107),
  [514] = {.entry = {.count = 1, .reusable = true}}, SHIFT(124),
  [516] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [518] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [520] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [522] = {.entry = {.count = 1, .reusable = true}}, SHIFT(70),
  [524] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [526] = {.entry = {.count = 1, .reusable = true}}, SHIFT(72),
  [528] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [530] = {.entry = {.count = 1, .reusable = true}}, SHIFT(74),
  [532] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [534] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [536] = {.entry = {.count = 1, .reusable = true}}, SHIFT(170),
  [538] = {.entry = {.count = 1, .reusable = true}}, SHIFT(171),
  [540] = {.entry = {.count = 1, .reusable = true}}, SHIFT(172),
  [542] = {.entry = {.count = 1, .reusable = true}}, SHIFT(173),
  [544] = {.entry = {.count = 1, .reusable = true}}, SHIFT(180),
  [546] = {.entry = {.count = 1, .reusable = true}}, SHIFT(186),
  [548] = {.entry = {.count = 1, .reusable = true}}, SHIFT(203),
  [550] = {.entry = {.count = 1, .reusable = true}}, SHIFT(175),
  [552] = {.entry = {.count = 1, .reusable = true}}, SHIFT(176),
  [554] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [556] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [558] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [560] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [562] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [564] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [566] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [568] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [570] = {.entry = {.count = 1, .reusable = true}}, SHIFT(190),
  [572] = {.entry = {.count = 1, .reusable = true}}, SHIFT(144),
  [574] = {.entry = {.count = 1, .reusable = true}}, SHIFT(149),
  [576] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [578] = {.entry = {.count = 1, .reusable = true}}, SHIFT(191),
  [580] = {.entry = {.count = 1, .reusable = true}}, SHIFT(192),
  [582] = {.entry = {.count = 1, .reusable = true}}, SHIFT(193),
  [584] = {.entry = {.count = 1, .reusable = true}}, SHIFT(84),
  [586] = {.entry = {.count = 1, .reusable = true}}, SHIFT(196),
  [588] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [590] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [592] = {.entry = {.count = 1, .reusable = true}}, SHIFT(148),
  [594] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [596] = {.entry = {.count = 1, .reusable = true}}, SHIFT(86),
  [598] = {.entry = {.count = 1, .reusable = true}}, SHIFT(150),
  [600] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [602] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [604] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [606] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [608] = {.entry = {.count = 1, .reusable = true}}, SHIFT(159),
  [610] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [612] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [614] = {.entry = {.count = 1, .reusable = true}}, SHIFT(102),
  [616] = {.entry = {.count = 1, .reusable = true}}, SHIFT(199),
  [618] = {.entry = {.count = 1, .reusable = true}}, SHIFT(200),
  [620] = {.entry = {.count = 1, .reusable = true}}, SHIFT(151),
  [622] = {.entry = {.count = 1, .reusable = true}}, SHIFT(153),
  [624] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [626] = {.entry = {.count = 1, .reusable = true}}, SHIFT(147),
  [628] = {.entry = {.count = 1, .reusable = true}}, SHIFT(201),
  [630] = {.entry = {.count = 1, .reusable = true}}, SHIFT(80),
  [632] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [634] = {.entry = {.count = 1, .reusable = true}}, SHIFT(155),
  [636] = {.entry = {.count = 1, .reusable = true}}, SHIFT(154),
  [638] = {.entry = {.count = 1, .reusable = true}}, SHIFT(93),
  [640] = {.entry = {.count = 1, .reusable = true}}, SHIFT(94),
  [642] = {.entry = {.count = 1, .reusable = true}}, SHIFT(90),
  [644] = {.entry = {.count = 1, .reusable = true}}, SHIFT(119),
  [646] = {.entry = {.count = 1, .reusable = true}}, SHIFT(152),
  [648] = {.entry = {.count = 1, .reusable = true}}, SHIFT(89),
  [650] = {.entry = {.count = 1, .reusable = true}}, SHIFT(126),
  [652] = {.entry = {.count = 1, .reusable = true}}, SHIFT(125),
  [654] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [656] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_map_string_array_field, 1),
  [658] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [660] = {.entry = {.count = 1, .reusable = true}}, SHIFT(146),
  [662] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [664] = {.entry = {.count = 1, .reusable = true}}, SHIFT(118),
  [666] = {.entry = {.count = 1, .reusable = true}}, SHIFT(121),
  [668] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [670] = {.entry = {.count = 1, .reusable = true}}, SHIFT(79),
  [672] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [674] = {.entry = {.count = 1, .reusable = true}}, SHIFT(88),
  [676] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [678] = {.entry = {.count = 1, .reusable = true}}, SHIFT(65),
  [680] = {.entry = {.count = 1, .reusable = true}}, SHIFT(219),
  [682] = {.entry = {.count = 1, .reusable = true}}, SHIFT(220),
  [684] = {.entry = {.count = 1, .reusable = true}}, SHIFT(221),
  [686] = {.entry = {.count = 1, .reusable = true}}, SHIFT(77),
  [688] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [690] = {.entry = {.count = 1, .reusable = true}}, SHIFT(227),
  [692] = {.entry = {.count = 1, .reusable = true}}, SHIFT(228),
  [694] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [696] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [698] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [700] = {.entry = {.count = 1, .reusable = true}}, SHIFT(229),
  [702] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [704] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [706] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [708] = {.entry = {.count = 1, .reusable = true}}, SHIFT(237),
  [710] = {.entry = {.count = 1, .reusable = true}}, SHIFT(241),
  [712] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [714] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
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
