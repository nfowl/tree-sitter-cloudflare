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
#define STATE_COUNT 166
#define LARGE_STATE_COUNT 45
#define SYMBOL_COUNT 152
#define ALIAS_COUNT 0
#define TOKEN_COUNT 106
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 15
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 14

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
  anon_sym_LBRACK = 51,
  anon_sym_RBRACK = 52,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTsec = 53,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec = 54,
  anon_sym_ip_DOTgeoip_DOTasnum = 55,
  anon_sym_cf_DOTbot_management_DOTscore = 56,
  anon_sym_cf_DOTedge_DOTserver_port = 57,
  anon_sym_cf_DOTthreat_score = 58,
  anon_sym_cf_DOTwaf_DOTscore = 59,
  anon_sym_cf_DOTwaf_DOTscore_DOTsqli = 60,
  anon_sym_cf_DOTwaf_DOTscore_DOTxss = 61,
  anon_sym_cf_DOTwaf_DOTscore_DOTrce = 62,
  anon_sym_ip_DOTsrc = 63,
  anon_sym_cf_DOTedge_DOTserver_ip = 64,
  anon_sym_http_DOTcookie = 65,
  anon_sym_http_DOThost = 66,
  anon_sym_http_DOTreferer = 67,
  anon_sym_http_DOTrequest_DOTfull_uri = 68,
  anon_sym_http_DOTrequest_DOTmethod = 69,
  anon_sym_http_DOTrequest_DOTuri = 70,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 71,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 72,
  anon_sym_http_DOTuser_agent = 73,
  anon_sym_http_DOTrequest_DOTversion = 74,
  anon_sym_http_DOTx_forwarded_for = 75,
  anon_sym_ip_DOTsrc_DOTlat = 76,
  anon_sym_ip_DOTsrc_DOTlon = 77,
  anon_sym_ip_DOTsrc_DOTcity = 78,
  anon_sym_ip_DOTsrc_DOTpostal_code = 79,
  anon_sym_ip_DOTsrc_DOTmetro_code = 80,
  anon_sym_ip_DOTgeoip_DOTcontinent = 81,
  anon_sym_ip_DOTgeoip_DOTcountry = 82,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 83,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 84,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 85,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 86,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 87,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 88,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 89,
  anon_sym_cf_DOThostname_DOTmetadata = 90,
  anon_sym_cf_DOTworker_DOTupstream_zone = 91,
  anon_sym_cf_DOTrandom_seed = 92,
  anon_sym_http_DOTrequest_DOTcookies = 93,
  anon_sym_http_DOTrequest_DOTheaders = 94,
  anon_sym_http_DOTrequest_DOTheaders_DOTnames = 95,
  anon_sym_http_DOTrequest_DOTheaders_DOTvalues = 96,
  anon_sym_http_DOTrequest_DOTaccepted_languages = 97,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 98,
  anon_sym_ssl = 99,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 100,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 101,
  anon_sym_cf_DOTclient_DOTbot = 102,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 103,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 104,
  anon_sym_http_DOTrequest_DOTheaders_DOTtruncated = 105,
  sym_source_file = 106,
  sym__expression = 107,
  sym_not_expression = 108,
  sym_in_expression = 109,
  sym_compound_expression = 110,
  sym_ip_set = 111,
  sym_string_set = 112,
  sym_number_set = 113,
  sym_simple_expression = 114,
  sym__bool_lhs = 115,
  sym__number_lhs = 116,
  sym__string_lhs = 117,
  sym_string_func = 118,
  sym_number_func = 119,
  sym_bool_func = 120,
  sym_concat_func = 121,
  sym_ends_with_func = 122,
  sym_len_func = 123,
  sym_lookup_func = 124,
  sym_lower_func = 125,
  sym_regex_replace_func = 126,
  sym_remove_bytes_func = 127,
  sym_starts_with_func = 128,
  sym_to_string_func = 129,
  sym_upper_func = 130,
  sym_url_decode_func = 131,
  sym_uuid_func = 132,
  sym_group = 133,
  sym_boolean = 134,
  sym__ip = 135,
  sym_ip_range = 136,
  sym_not_operator = 137,
  sym__stringlike_field = 138,
  sym_number_field = 139,
  sym_ip_field = 140,
  sym_string_field = 141,
  sym_bytes_field = 142,
  sym_map_string_array_field = 143,
  sym_array_string_field = 144,
  sym_bool_field = 145,
  aux_sym_source_file_repeat1 = 146,
  aux_sym_ip_set_repeat1 = 147,
  aux_sym_string_set_repeat1 = 148,
  aux_sym_number_set_repeat1 = 149,
  aux_sym_concat_func_repeat1 = 150,
  aux_sym_lookup_func_repeat1 = 151,
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
  [anon_sym_LBRACK] = "[",
  [anon_sym_RBRACK] = "]",
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
  [anon_sym_LBRACK] = anon_sym_LBRACK,
  [anon_sym_RBRACK] = anon_sym_RBRACK,
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
  [anon_sym_LBRACK] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RBRACK] = {
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
  field_index = 2,
  field_inner = 3,
  field_ip = 4,
  field_key = 5,
  field_keys = 6,
  field_lhs = 7,
  field_mask = 8,
  field_operator = 9,
  field_regex = 10,
  field_replacement = 11,
  field_rhs = 12,
  field_seed = 13,
  field_source = 14,
  field_value = 15,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_field] = "field",
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
  [1] = {.index = 0, .length = 2},
  [2] = {.index = 2, .length = 1},
  [3] = {.index = 3, .length = 3},
  [4] = {.index = 6, .length = 5},
  [5] = {.index = 11, .length = 1},
  [6] = {.index = 12, .length = 1},
  [7] = {.index = 13, .length = 1},
  [8] = {.index = 14, .length = 2},
  [9] = {.index = 16, .length = 2},
  [10] = {.index = 18, .length = 2},
  [11] = {.index = 20, .length = 2},
  [12] = {.index = 22, .length = 2},
  [13] = {.index = 24, .length = 3},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_index, 0, .inherited = true},
    {field_key, 0, .inherited = true},
  [2] =
    {field_inner, 1},
  [3] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [6] =
    {field_index, 0, .inherited = true},
    {field_key, 0, .inherited = true},
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [11] =
    {field_field, 2},
  [12] =
    {field_seed, 2},
  [13] =
    {field_index, 2},
  [14] =
    {field_field, 2},
    {field_keys, 3},
  [16] =
    {field_ip, 0},
    {field_mask, 2},
  [18] =
    {field_field, 2},
    {field_value, 4},
  [20] =
    {field_field, 2},
    {field_replacement, 4},
  [22] =
    {field_index, 5},
    {field_key, 2},
  [24] =
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
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(694);
      if (lookahead == '!') ADVANCE(756);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(704);
      if (lookahead == '$') ADVANCE(752);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(722);
      if (lookahead == ')') ADVANCE(724);
      if (lookahead == ',') ADVANCE(723);
      if (lookahead == '/') ADVANCE(746);
      if (lookahead == '3') ADVANCE(736);
      if (lookahead == '<') ADVANCE(714);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '>') ADVANCE(716);
      if (lookahead == '[') ADVANCE(757);
      if (lookahead == ']') ADVANCE(758);
      if (lookahead == '^') ADVANCE(53);
      if (lookahead == 'a') ADVANCE(395);
      if (lookahead == 'c') ADVANCE(288);
      if (lookahead == 'e') ADVANCE(405);
      if (lookahead == 'f') ADVANCE(91);
      if (lookahead == 'g') ADVANCE(196);
      if (lookahead == 'h') ADVANCE(608);
      if (lookahead == 'i') ADVANCE(396);
      if (lookahead == 'l') ADVANCE(197);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(199);
      if (lookahead == 'o') ADVANCE(509);
      if (lookahead == 'r') ADVANCE(93);
      if (lookahead == 's') ADVANCE(566);
      if (lookahead == 't') ADVANCE(439);
      if (lookahead == 'u') ADVANCE(485);
      if (lookahead == 'x') ADVANCE(443);
      if (lookahead == '{') ADVANCE(702);
      if (lookahead == '|') ADVANCE(692);
      if (lookahead == '}') ADVANCE(703);
      if (lookahead == '~') ADVANCE(720);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(737);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(737);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(51);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(704);
      if (lookahead == ')') ADVANCE(724);
      if (lookahead == ',') ADVANCE(723);
      if (lookahead == '<') ADVANCE(714);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '>') ADVANCE(716);
      if (lookahead == 'c') ADVANCE(292);
      if (lookahead == 'e') ADVANCE(506);
      if (lookahead == 'g') ADVANCE(196);
      if (lookahead == 'h') ADVANCE(650);
      if (lookahead == 'i') ADVANCE(397);
      if (lookahead == 'l') ADVANCE(218);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(198);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == '}') ADVANCE(703);
      if (lookahead == '~') ADVANCE(720);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(737);
      END_STATE();
    case 2:
      if (lookahead == '"') ADVANCE(738);
      if (lookahead != 0) ADVANCE(2);
      END_STATE();
    case 3:
      if (lookahead == '#') ADVANCE(704);
      if (lookahead == '3') ADVANCE(748);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(749);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(747);
      END_STATE();
    case 4:
      if (lookahead == '&') ADVANCE(696);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(136);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(303);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(147);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(159);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(110);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(126);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(299);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(358);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(389);
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
      if (lookahead == '.') ADVANCE(137);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(141);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(151);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(290);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(321);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(360);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(139);
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
      if (lookahead == '.') ADVANCE(569);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(163);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(500);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(309);
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
      if (lookahead == '.') ADVANCE(656);
      END_STATE();
    case 41:
      if (lookahead == '.') ADVANCE(386);
      END_STATE();
    case 42:
      if (lookahead == '.') ADVANCE(541);
      END_STATE();
    case 43:
      if (lookahead == '.') ADVANCE(592);
      END_STATE();
    case 44:
      if (lookahead == '.') ADVANCE(148);
      END_STATE();
    case 45:
      if (lookahead == '1') ADVANCE(70);
      if (lookahead == '2') ADVANCE(90);
      END_STATE();
    case 46:
      if (lookahead == '2') ADVANCE(742);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(745);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(744);
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
      if (lookahead == '3') ADVANCE(67);
      END_STATE();
    case 50:
      if (lookahead == '4') ADVANCE(735);
      END_STATE();
    case 51:
      if (lookahead == '=') ADVANCE(713);
      END_STATE();
    case 52:
      if (lookahead == '=') ADVANCE(712);
      END_STATE();
    case 53:
      if (lookahead == '^') ADVANCE(699);
      END_STATE();
    case 54:
      if (lookahead == '_') ADVANCE(382);
      END_STATE();
    case 55:
      if (lookahead == '_') ADVANCE(359);
      END_STATE();
    case 56:
      if (lookahead == '_') ADVANCE(135);
      END_STATE();
    case 57:
      if (lookahead == '_') ADVANCE(332);
      END_STATE();
    case 58:
      if (lookahead == '_') ADVANCE(45);
      END_STATE();
    case 59:
      if (lookahead == '_') ADVANCE(548);
      END_STATE();
    case 60:
      if (lookahead == '_') ADVANCE(678);
      END_STATE();
    case 61:
      if (lookahead == '_') ADVANCE(293);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(690);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(570);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(164);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(183);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(495);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(320);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(104);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(375);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(348);
      END_STATE();
    case 71:
      if (lookahead == '_') ADVANCE(227);
      END_STATE();
    case 72:
      if (lookahead == '_') ADVANCE(583);
      END_STATE();
    case 73:
      if (lookahead == '_') ADVANCE(532);
      END_STATE();
    case 74:
      if (lookahead == '_') ADVANCE(662);
      END_STATE();
    case 75:
      if (lookahead == '_') ADVANCE(660);
      END_STATE();
    case 76:
      if (lookahead == '_') ADVANCE(347);
      END_STATE();
    case 77:
      if (lookahead == '_') ADVANCE(664);
      END_STATE();
    case 78:
      if (lookahead == '_') ADVANCE(190);
      END_STATE();
    case 79:
      if (lookahead == '_') ADVANCE(681);
      END_STATE();
    case 80:
      if (lookahead == '_') ADVANCE(294);
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
      if (lookahead == '_') ADVANCE(594);
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
      if (lookahead == '_') ADVANCE(595);
      END_STATE();
    case 89:
      if (lookahead == '_') ADVANCE(394);
      END_STATE();
    case 90:
      if (lookahead == '_') ADVANCE(357);
      END_STATE();
    case 91:
      if (lookahead == 'a') ADVANCE(369);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(677);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(677);
      if (lookahead == 'e') ADVANCE(302);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(289);
      if (lookahead == 'o') ADVANCE(516);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(49);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(49);
      if (lookahead == 's') ADVANCE(78);
      END_STATE();
    case 97:
      if (lookahead == 'a') ADVANCE(796);
      END_STATE();
    case 98:
      if (lookahead == 'a') ADVANCE(410);
      if (lookahead == 'b') ADVANCE(452);
      if (lookahead == 'm') ADVANCE(103);
      if (lookahead == 'o') ADVANCE(494);
      if (lookahead == 'v') ADVANCE(488);
      END_STATE();
    case 99:
      if (lookahead == 'a') ADVANCE(598);
      END_STATE();
    case 100:
      if (lookahead == 'a') ADVANCE(520);
      END_STATE();
    case 101:
      if (lookahead == 'a') ADVANCE(331);
      END_STATE();
    case 102:
      if (lookahead == 'a') ADVANCE(385);
      END_STATE();
    case 103:
      if (lookahead == 'a') ADVANCE(370);
      END_STATE();
    case 104:
      if (lookahead == 'a') ADVANCE(663);
      END_STATE();
    case 105:
      if (lookahead == 'a') ADVANCE(384);
      END_STATE();
    case 106:
      if (lookahead == 'a') ADVANCE(380);
      END_STATE();
    case 107:
      if (lookahead == 'a') ADVANCE(390);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(600);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(153);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(580);
      if (lookahead == 'c') ADVANCE(442);
      if (lookahead == 'i') ADVANCE(575);
      if (lookahead == 's') ADVANCE(653);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(193);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(194);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(376);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(414);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(641);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(602);
      if (lookahead == 'o') ADVANCE(402);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(551);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(573);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(409);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(591);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(627);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(619);
      END_STATE();
    case 123:
      if (lookahead == 'a') ADVANCE(622);
      END_STATE();
    case 124:
      if (lookahead == 'a') ADVANCE(411);
      END_STATE();
    case 125:
      if (lookahead == 'a') ADVANCE(306);
      END_STATE();
    case 126:
      if (lookahead == 'a') ADVANCE(161);
      if (lookahead == 'c') ADVANCE(481);
      if (lookahead == 'f') ADVANCE(657);
      if (lookahead == 'h') ADVANCE(239);
      if (lookahead == 'm') ADVANCE(262);
      if (lookahead == 't') ADVANCE(353);
      if (lookahead == 'u') ADVANCE(524);
      if (lookahead == 'v') ADVANCE(258);
      END_STATE();
    case 127:
      if (lookahead == 'a') ADVANCE(308);
      END_STATE();
    case 128:
      if (lookahead == 'a') ADVANCE(540);
      END_STATE();
    case 129:
      if (lookahead == 'a') ADVANCE(307);
      END_STATE();
    case 130:
      if (lookahead == 'a') ADVANCE(424);
      END_STATE();
    case 131:
      if (lookahead == 'a') ADVANCE(639);
      END_STATE();
    case 132:
      if (lookahead == 'a') ADVANCE(387);
      END_STATE();
    case 133:
      if (lookahead == 'a') ADVANCE(310);
      END_STATE();
    case 134:
      if (lookahead == 'a') ADVANCE(436);
      END_STATE();
    case 135:
      if (lookahead == 'b') ADVANCE(689);
      END_STATE();
    case 136:
      if (lookahead == 'b') ADVANCE(450);
      if (lookahead == 'c') ADVANCE(368);
      if (lookahead == 'e') ADVANCE(173);
      if (lookahead == 'h') ADVANCE(465);
      if (lookahead == 'r') ADVANCE(124);
      if (lookahead == 't') ADVANCE(317);
      if (lookahead == 'w') ADVANCE(94);
      END_STATE();
    case 137:
      if (lookahead == 'b') ADVANCE(450);
      if (lookahead == 'c') ADVANCE(368);
      if (lookahead == 'e') ADVANCE(173);
      if (lookahead == 'h') ADVANCE(465);
      if (lookahead == 't') ADVANCE(317);
      if (lookahead == 'w') ADVANCE(94);
      END_STATE();
    case 138:
      if (lookahead == 'b') ADVANCE(181);
      END_STATE();
    case 139:
      if (lookahead == 'b') ADVANCE(460);
      END_STATE();
    case 140:
      if (lookahead == 'b') ADVANCE(463);
      END_STATE();
    case 141:
      if (lookahead == 'b') ADVANCE(484);
      if (lookahead == 'h') ADVANCE(465);
      if (lookahead == 'w') ADVANCE(451);
      END_STATE();
    case 142:
      if (lookahead == 'c') ADVANCE(316);
      END_STATE();
    case 143:
      if (lookahead == 'c') ADVANCE(769);
      END_STATE();
    case 144:
      if (lookahead == 'c') ADVANCE(750);
      END_STATE();
    case 145:
      if (lookahead == 'c') ADVANCE(759);
      END_STATE();
    case 146:
      if (lookahead == 'c') ADVANCE(760);
      END_STATE();
    case 147:
      if (lookahead == 'c') ADVANCE(453);
      if (lookahead == 'h') ADVANCE(468);
      if (lookahead == 'r') ADVANCE(204);
      if (lookahead == 'u') ADVANCE(590);
      if (lookahead == 'x') ADVANCE(61);
      END_STATE();
    case 148:
      if (lookahead == 'c') ADVANCE(453);
      if (lookahead == 'h') ADVANCE(468);
      if (lookahead == 'r') ADVANCE(286);
      if (lookahead == 'u') ADVANCE(590);
      if (lookahead == 'x') ADVANCE(61);
      END_STATE();
    case 149:
      if (lookahead == 'c') ADVANCE(144);
      END_STATE();
    case 150:
      if (lookahead == 'c') ADVANCE(466);
      END_STATE();
    case 151:
      if (lookahead == 'c') ADVANCE(442);
      if (lookahead == 's') ADVANCE(653);
      END_STATE();
    case 152:
      if (lookahead == 'c') ADVANCE(8);
      END_STATE();
    case 153:
      if (lookahead == 'c') ADVANCE(209);
      END_STATE();
    case 154:
      if (lookahead == 'c') ADVANCE(211);
      END_STATE();
    case 155:
      if (lookahead == 'c') ADVANCE(647);
      END_STATE();
    case 156:
      if (lookahead == 'c') ADVANCE(233);
      END_STATE();
    case 157:
      if (lookahead == 'c') ADVANCE(108);
      END_STATE();
    case 158:
      if (lookahead == 'c') ADVANCE(108);
      if (lookahead == 't') ADVANCE(101);
      END_STATE();
    case 159:
      if (lookahead == 'c') ADVANCE(337);
      if (lookahead == 'l') ADVANCE(116);
      if (lookahead == 'm') ADVANCE(268);
      if (lookahead == 'p') ADVANCE(471);
      END_STATE();
    case 160:
      if (lookahead == 'c') ADVANCE(474);
      END_STATE();
    case 161:
      if (lookahead == 'c') ADVANCE(156);
      END_STATE();
    case 162:
      if (lookahead == 'c') ADVANCE(131);
      END_STATE();
    case 163:
      if (lookahead == 'c') ADVANCE(273);
      END_STATE();
    case 164:
      if (lookahead == 'c') ADVANCE(377);
      END_STATE();
    case 165:
      if (lookahead == 'c') ADVANCE(472);
      END_STATE();
    case 166:
      if (lookahead == 'c') ADVANCE(475);
      END_STATE();
    case 167:
      if (lookahead == 'c') ADVANCE(473);
      END_STATE();
    case 168:
      if (lookahead == 'c') ADVANCE(478);
      END_STATE();
    case 169:
      if (lookahead == 'c') ADVANCE(476);
      END_STATE();
    case 170:
      if (lookahead == 'c') ADVANCE(477);
      END_STATE();
    case 171:
      if (lookahead == 'd') ADVANCE(697);
      END_STATE();
    case 172:
      if (lookahead == 'd') ADVANCE(567);
      END_STATE();
    case 173:
      if (lookahead == 'd') ADVANCE(305);
      END_STATE();
    case 174:
      if (lookahead == 'd') ADVANCE(798);
      END_STATE();
    case 175:
      if (lookahead == 'd') ADVANCE(775);
      END_STATE();
    case 176:
      if (lookahead == 'd') ADVANCE(811);
      END_STATE();
    case 177:
      if (lookahead == 'd') ADVANCE(809);
      END_STATE();
    case 178:
      if (lookahead == 'd') ADVANCE(810);
      END_STATE();
    case 179:
      if (lookahead == 'd') ADVANCE(807);
      END_STATE();
    case 180:
      if (lookahead == 'd') ADVANCE(672);
      END_STATE();
    case 181:
      if (lookahead == 'd') ADVANCE(330);
      END_STATE();
    case 182:
      if (lookahead == 'd') ADVANCE(445);
      END_STATE();
    case 183:
      if (lookahead == 'd') ADVANCE(219);
      END_STATE();
    case 184:
      if (lookahead == 'd') ADVANCE(205);
      END_STATE();
    case 185:
      if (lookahead == 'd') ADVANCE(69);
      END_STATE();
    case 186:
      if (lookahead == 'd') ADVANCE(81);
      END_STATE();
    case 187:
      if (lookahead == 'd') ADVANCE(231);
      END_STATE();
    case 188:
      if (lookahead == 'd') ADVANCE(212);
      END_STATE();
    case 189:
      if (lookahead == 'd') ADVANCE(213);
      END_STATE();
    case 190:
      if (lookahead == 'd') ADVANCE(276);
      END_STATE();
    case 191:
      if (lookahead == 'd') ADVANCE(216);
      END_STATE();
    case 192:
      if (lookahead == 'd') ADVANCE(217);
      END_STATE();
    case 193:
      if (lookahead == 'd') ADVANCE(121);
      END_STATE();
    case 194:
      if (lookahead == 'd') ADVANCE(260);
      END_STATE();
    case 195:
      if (lookahead == 'd') ADVANCE(80);
      END_STATE();
    case 196:
      if (lookahead == 'e') ADVANCE(711);
      if (lookahead == 't') ADVANCE(710);
      END_STATE();
    case 197:
      if (lookahead == 'e') ADVANCE(709);
      if (lookahead == 'o') ADVANCE(440);
      if (lookahead == 't') ADVANCE(707);
      END_STATE();
    case 198:
      if (lookahead == 'e') ADVANCE(706);
      END_STATE();
    case 199:
      if (lookahead == 'e') ADVANCE(706);
      if (lookahead == 'o') ADVANCE(599);
      END_STATE();
    case 200:
      if (lookahead == 'e') ADVANCE(682);
      END_STATE();
    case 201:
      if (lookahead == 'e') ADVANCE(739);
      END_STATE();
    case 202:
      if (lookahead == 'e') ADVANCE(740);
      END_STATE();
    case 203:
      if (lookahead == 'e') ADVANCE(750);
      END_STATE();
    case 204:
      if (lookahead == 'e') ADVANCE(295);
      END_STATE();
    case 205:
      if (lookahead == 'e') ADVANCE(734);
      END_STATE();
    case 206:
      if (lookahead == 'e') ADVANCE(771);
      END_STATE();
    case 207:
      if (lookahead == 'e') ADVANCE(508);
      END_STATE();
    case 208:
      if (lookahead == 'e') ADVANCE(765);
      END_STATE();
    case 209:
      if (lookahead == 'e') ADVANCE(729);
      END_STATE();
    case 210:
      if (lookahead == 'e') ADVANCE(764);
      END_STATE();
    case 211:
      if (lookahead == 'e') ADVANCE(768);
      END_STATE();
    case 212:
      if (lookahead == 'e') ADVANCE(786);
      END_STATE();
    case 213:
      if (lookahead == 'e') ADVANCE(785);
      END_STATE();
    case 214:
      if (lookahead == 'e') ADVANCE(762);
      END_STATE();
    case 215:
      if (lookahead == 'e') ADVANCE(797);
      END_STATE();
    case 216:
      if (lookahead == 'e') ADVANCE(789);
      END_STATE();
    case 217:
      if (lookahead == 'e') ADVANCE(790);
      END_STATE();
    case 218:
      if (lookahead == 'e') ADVANCE(708);
      if (lookahead == 't') ADVANCE(707);
      END_STATE();
    case 219:
      if (lookahead == 'e') ADVANCE(150);
      END_STATE();
    case 220:
      if (lookahead == 'e') ADVANCE(511);
      END_STATE();
    case 221:
      if (lookahead == 'e') ADVANCE(448);
      END_STATE();
    case 222:
      if (lookahead == 'e') ADVANCE(490);
      END_STATE();
    case 223:
      if (lookahead == 'e') ADVANCE(557);
      END_STATE();
    case 224:
      if (lookahead == 'e') ADVANCE(675);
      END_STATE();
    case 225:
      if (lookahead == 'e') ADVANCE(512);
      END_STATE();
    case 226:
      if (lookahead == 'e') ADVANCE(43);
      END_STATE();
    case 227:
      if (lookahead == 'e') ADVANCE(661);
      END_STATE();
    case 228:
      if (lookahead == 'e') ADVANCE(415);
      END_STATE();
    case 229:
      if (lookahead == 'e') ADVANCE(174);
      END_STATE();
    case 230:
      if (lookahead == 'e') ADVANCE(417);
      END_STATE();
    case 231:
      if (lookahead == 'e') ADVANCE(195);
      END_STATE();
    case 232:
      if (lookahead == 'e') ADVANCE(56);
      END_STATE();
    case 233:
      if (lookahead == 'e') ADVANCE(501);
      END_STATE();
    case 234:
      if (lookahead == 'e') ADVANCE(525);
      END_STATE();
    case 235:
      if (lookahead == 'e') ADVANCE(559);
      END_STATE();
    case 236:
      if (lookahead == 'e') ADVANCE(155);
      END_STATE();
    case 237:
      if (lookahead == 'e') ADVANCE(526);
      END_STATE();
    case 238:
      if (lookahead == 'e') ADVANCE(41);
      END_STATE();
    case 239:
      if (lookahead == 'e') ADVANCE(112);
      END_STATE();
    case 240:
      if (lookahead == 'e') ADVANCE(553);
      END_STATE();
    case 241:
      if (lookahead == 'e') ADVANCE(556);
      END_STATE();
    case 242:
      if (lookahead == 'e') ADVANCE(145);
      END_STATE();
    case 243:
      if (lookahead == 'e') ADVANCE(105);
      END_STATE();
    case 244:
      if (lookahead == 'e') ADVANCE(185);
      END_STATE();
    case 245:
      if (lookahead == 'e') ADVANCE(146);
      END_STATE();
    case 246:
      if (lookahead == 'e') ADVANCE(176);
      END_STATE();
    case 247:
      if (lookahead == 'e') ADVANCE(616);
      END_STATE();
    case 248:
      if (lookahead == 'e') ADVANCE(518);
      END_STATE();
    case 249:
      if (lookahead == 'e') ADVANCE(177);
      END_STATE();
    case 250:
      if (lookahead == 'e') ADVANCE(178);
      END_STATE();
    case 251:
      if (lookahead == 'e') ADVANCE(561);
      END_STATE();
    case 252:
      if (lookahead == 'e') ADVANCE(514);
      END_STATE();
    case 253:
      if (lookahead == 'e') ADVANCE(179);
      END_STATE();
    case 254:
      if (lookahead == 'e') ADVANCE(513);
      END_STATE();
    case 255:
      if (lookahead == 'e') ADVANCE(563);
      END_STATE();
    case 256:
      if (lookahead == 'e') ADVANCE(564);
      END_STATE();
    case 257:
      if (lookahead == 'e') ADVANCE(565);
      END_STATE();
    case 258:
      if (lookahead == 'e') ADVANCE(531);
      END_STATE();
    case 259:
      if (lookahead == 'e') ADVANCE(399);
      if (lookahead == 'o') ADVANCE(440);
      END_STATE();
    case 260:
      if (lookahead == 'e') ADVANCE(538);
      END_STATE();
    case 261:
      if (lookahead == 'e') ADVANCE(624);
      END_STATE();
    case 262:
      if (lookahead == 'e') ADVANCE(615);
      END_STATE();
    case 263:
      if (lookahead == 'e') ADVANCE(229);
      END_STATE();
    case 264:
      if (lookahead == 'e') ADVANCE(537);
      END_STATE();
    case 265:
      if (lookahead == 'e') ADVANCE(521);
      END_STATE();
    case 266:
      if (lookahead == 'e') ADVANCE(522);
      END_STATE();
    case 267:
      if (lookahead == 'e') ADVANCE(130);
      END_STATE();
    case 268:
      if (lookahead == 'e') ADVANCE(631);
      END_STATE();
    case 269:
      if (lookahead == 'e') ADVANCE(422);
      END_STATE();
    case 270:
      if (lookahead == 'e') ADVANCE(534);
      END_STATE();
    case 271:
      if (lookahead == 'e') ADVANCE(186);
      END_STATE();
    case 272:
      if (lookahead == 'e') ADVANCE(115);
      END_STATE();
    case 273:
      if (lookahead == 'e') ADVANCE(545);
      END_STATE();
    case 274:
      if (lookahead == 'e') ADVANCE(391);
      END_STATE();
    case 275:
      if (lookahead == 'e') ADVANCE(425);
      END_STATE();
    case 276:
      if (lookahead == 'e') ADVANCE(638);
      END_STATE();
    case 277:
      if (lookahead == 'e') ADVANCE(426);
      END_STATE();
    case 278:
      if (lookahead == 'e') ADVANCE(582);
      END_STATE();
    case 279:
      if (lookahead == 'e') ADVANCE(427);
      END_STATE();
    case 280:
      if (lookahead == 'e') ADVANCE(584);
      END_STATE();
    case 281:
      if (lookahead == 'e') ADVANCE(585);
      END_STATE();
    case 282:
      if (lookahead == 'e') ADVANCE(429);
      END_STATE();
    case 283:
      if (lookahead == 'e') ADVANCE(586);
      END_STATE();
    case 284:
      if (lookahead == 'e') ADVANCE(555);
      END_STATE();
    case 285:
      if (lookahead == 'e') ADVANCE(392);
      END_STATE();
    case 286:
      if (lookahead == 'e') ADVANCE(296);
      END_STATE();
    case 287:
      if (lookahead == 'e') ADVANCE(480);
      END_STATE();
    case 288:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(398);
      END_STATE();
    case 289:
      if (lookahead == 'f') ADVANCE(31);
      END_STATE();
    case 290:
      if (lookahead == 'f') ADVANCE(657);
      if (lookahead == 'm') ADVANCE(262);
      if (lookahead == 'u') ADVANCE(524);
      if (lookahead == 'v') ADVANCE(258);
      END_STATE();
    case 291:
      if (lookahead == 'f') ADVANCE(19);
      if (lookahead == 'o') ADVANCE(434);
      END_STATE();
    case 292:
      if (lookahead == 'f') ADVANCE(20);
      if (lookahead == 'o') ADVANCE(428);
      END_STATE();
    case 293:
      if (lookahead == 'f') ADVANCE(455);
      END_STATE();
    case 294:
      if (lookahead == 'f') ADVANCE(462);
      END_STATE();
    case 295:
      if (lookahead == 'f') ADVANCE(240);
      if (lookahead == 'q') ADVANCE(658);
      END_STATE();
    case 296:
      if (lookahead == 'f') ADVANCE(240);
      if (lookahead == 'q') ADVANCE(670);
      END_STATE();
    case 297:
      if (lookahead == 'f') ADVANCE(351);
      END_STATE();
    case 298:
      if (lookahead == 'f') ADVANCE(344);
      END_STATE();
    case 299:
      if (lookahead == 'f') ADVANCE(671);
      if (lookahead == 'u') ADVANCE(530);
      END_STATE();
    case 300:
      if (lookahead == 'g') ADVANCE(732);
      END_STATE();
    case 301:
      if (lookahead == 'g') ADVANCE(727);
      END_STATE();
    case 302:
      if (lookahead == 'g') ADVANCE(200);
      if (lookahead == 'm') ADVANCE(441);
      END_STATE();
    case 303:
      if (lookahead == 'g') ADVANCE(221);
      if (lookahead == 's') ADVANCE(517);
      END_STATE();
    case 304:
      if (lookahead == 'g') ADVANCE(669);
      END_STATE();
    case 305:
      if (lookahead == 'g') ADVANCE(226);
      END_STATE();
    case 306:
      if (lookahead == 'g') ADVANCE(274);
      END_STATE();
    case 307:
      if (lookahead == 'g') ADVANCE(257);
      END_STATE();
    case 308:
      if (lookahead == 'g') ADVANCE(275);
      END_STATE();
    case 309:
      if (lookahead == 'g') ADVANCE(287);
      if (lookahead == 's') ADVANCE(533);
      END_STATE();
    case 310:
      if (lookahead == 'g') ADVANCE(285);
      END_STATE();
    case 311:
      if (lookahead == 'h') ADVANCE(725);
      END_STATE();
    case 312:
      if (lookahead == 'h') ADVANCE(731);
      END_STATE();
    case 313:
      if (lookahead == 'h') ADVANCE(777);
      END_STATE();
    case 314:
      if (lookahead == 'h') ADVANCE(793);
      END_STATE();
    case 315:
      if (lookahead == 'h') ADVANCE(795);
      END_STATE();
    case 316:
      if (lookahead == 'h') ADVANCE(223);
      END_STATE();
    case 317:
      if (lookahead == 'h') ADVANCE(527);
      if (lookahead == 'l') ADVANCE(571);
      END_STATE();
    case 318:
      if (lookahead == 'h') ADVANCE(454);
      END_STATE();
    case 319:
      if (lookahead == 'h') ADVANCE(32);
      END_STATE();
    case 320:
      if (lookahead == 'h') ADVANCE(118);
      END_STATE();
    case 321:
      if (lookahead == 'h') ADVANCE(645);
      END_STATE();
    case 322:
      if (lookahead == 'i') ADVANCE(691);
      END_STATE();
    case 323:
      if (lookahead == 'i') ADVANCE(776);
      END_STATE();
    case 324:
      if (lookahead == 'i') ADVANCE(766);
      END_STATE();
    case 325:
      if (lookahead == 'i') ADVANCE(792);
      END_STATE();
    case 326:
      if (lookahead == 'i') ADVANCE(774);
      END_STATE();
    case 327:
      if (lookahead == 'i') ADVANCE(791);
      END_STATE();
    case 328:
      if (lookahead == 'i') ADVANCE(180);
      END_STATE();
    case 329:
      if (lookahead == 'i') ADVANCE(297);
      END_STATE();
    case 330:
      if (lookahead == 'i') ADVANCE(674);
      END_STATE();
    case 331:
      if (lookahead == 'i') ADVANCE(413);
      END_STATE();
    case 332:
      if (lookahead == 'i') ADVANCE(486);
      if (lookahead == 'p') ADVANCE(464);
      END_STATE();
    case 333:
      if (lookahead == 'i') ADVANCE(230);
      END_STATE();
    case 334:
      if (lookahead == 'i') ADVANCE(406);
      END_STATE();
    case 335:
      if (lookahead == 'i') ADVANCE(610);
      END_STATE();
    case 336:
      if (lookahead == 'i') ADVANCE(577);
      END_STATE();
    case 337:
      if (lookahead == 'i') ADVANCE(611);
      END_STATE();
    case 338:
      if (lookahead == 'i') ADVANCE(407);
      END_STATE();
    case 339:
      if (lookahead == 'i') ADVANCE(470);
      END_STATE();
    case 340:
      if (lookahead == 'i') ADVANCE(612);
      END_STATE();
    case 341:
      if (lookahead == 'i') ADVANCE(206);
      END_STATE();
    case 342:
      if (lookahead == 'i') ADVANCE(241);
      END_STATE();
    case 343:
      if (lookahead == 'i') ADVANCE(251);
      END_STATE();
    case 344:
      if (lookahead == 'i') ADVANCE(250);
      END_STATE();
    case 345:
      if (lookahead == 'i') ADVANCE(491);
      END_STATE();
    case 346:
      if (lookahead == 'i') ADVANCE(433);
      END_STATE();
    case 347:
      if (lookahead == 'i') ADVANCE(419);
      END_STATE();
    case 348:
      if (lookahead == 'i') ADVANCE(596);
      END_STATE();
    case 349:
      if (lookahead == 'i') ADVANCE(269);
      END_STATE();
    case 350:
      if (lookahead == 'i') ADVANCE(458);
      END_STATE();
    case 351:
      if (lookahead == 'i') ADVANCE(271);
      END_STATE();
    case 352:
      if (lookahead == 'i') ADVANCE(459);
      END_STATE();
    case 353:
      if (lookahead == 'i') ADVANCE(393);
      END_STATE();
    case 354:
      if (lookahead == 'i') ADVANCE(461);
      END_STATE();
    case 355:
      if (lookahead == 'i') ADVANCE(497);
      END_STATE();
    case 356:
      if (lookahead == 'i') ADVANCE(298);
      END_STATE();
    case 357:
      if (lookahead == 'i') ADVANCE(597);
      END_STATE();
    case 358:
      if (lookahead == 'j') ADVANCE(96);
      if (lookahead == 's') ADVANCE(168);
      if (lookahead == 'v') ADVANCE(264);
      END_STATE();
    case 359:
      if (lookahead == 'j') ADVANCE(574);
      END_STATE();
    case 360:
      if (lookahead == 'j') ADVANCE(95);
      END_STATE();
    case 361:
      if (lookahead == 'k') ADVANCE(654);
      END_STATE();
    case 362:
      if (lookahead == 'k') ADVANCE(249);
      END_STATE();
    case 363:
      if (lookahead == 'k') ADVANCE(341);
      END_STATE();
    case 364:
      if (lookahead == 'k') ADVANCE(234);
      END_STATE();
    case 365:
      if (lookahead == 'k') ADVANCE(343);
      END_STATE();
    case 366:
      if (lookahead == 'l') ADVANCE(805);
      END_STATE();
    case 367:
      if (lookahead == 'l') ADVANCE(65);
      END_STATE();
    case 368:
      if (lookahead == 'l') ADVANCE(333);
      END_STATE();
    case 369:
      if (lookahead == 'l') ADVANCE(568);
      END_STATE();
    case 370:
      if (lookahead == 'l') ADVANCE(679);
      END_STATE();
    case 371:
      if (lookahead == 'l') ADVANCE(109);
      END_STATE();
    case 372:
      if (lookahead == 'l') ADVANCE(324);
      END_STATE();
    case 373:
      if (lookahead == 'l') ADVANCE(74);
      END_STATE();
    case 374:
      if (lookahead == 'l') ADVANCE(373);
      END_STATE();
    case 375:
      if (lookahead == 'l') ADVANCE(119);
      END_STATE();
    case 376:
      if (lookahead == 'l') ADVANCE(665);
      END_STATE();
    case 377:
      if (lookahead == 'l') ADVANCE(349);
      END_STATE();
    case 378:
      if (lookahead == 'l') ADVANCE(77);
      END_STATE();
    case 379:
      if (lookahead == 'l') ADVANCE(378);
      END_STATE();
    case 380:
      if (lookahead == 'l') ADVANCE(85);
      END_STATE();
    case 381:
      if (lookahead == 'm') ADVANCE(761);
      END_STATE();
    case 382:
      if (lookahead == 'm') ADVANCE(114);
      END_STATE();
    case 383:
      if (lookahead == 'm') ADVANCE(322);
      END_STATE();
    case 384:
      if (lookahead == 'm') ADVANCE(62);
      END_STATE();
    case 385:
      if (lookahead == 'm') ADVANCE(238);
      END_STATE();
    case 386:
      if (lookahead == 'm') ADVANCE(261);
      END_STATE();
    case 387:
      if (lookahead == 'm') ADVANCE(255);
      END_STATE();
    case 388:
      if (lookahead == 'm') ADVANCE(72);
      END_STATE();
    case 389:
      if (lookahead == 'm') ADVANCE(587);
      if (lookahead == 's') ADVANCE(242);
      END_STATE();
    case 390:
      if (lookahead == 'm') ADVANCE(496);
      END_STATE();
    case 391:
      if (lookahead == 'm') ADVANCE(277);
      END_STATE();
    case 392:
      if (lookahead == 'm') ADVANCE(282);
      END_STATE();
    case 393:
      if (lookahead == 'm') ADVANCE(281);
      END_STATE();
    case 394:
      if (lookahead == 'm') ADVANCE(134);
      END_STATE();
    case 395:
      if (lookahead == 'n') ADVANCE(171);
      END_STATE();
    case 396:
      if (lookahead == 'n') ADVANCE(695);
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 397:
      if (lookahead == 'n') ADVANCE(695);
      if (lookahead == 'p') ADVANCE(34);
      END_STATE();
    case 398:
      if (lookahead == 'n') ADVANCE(158);
      END_STATE();
    case 399:
      if (lookahead == 'n') ADVANCE(726);
      END_STATE();
    case 400:
      if (lookahead == 'n') ADVANCE(750);
      END_STATE();
    case 401:
      if (lookahead == 'n') ADVANCE(688);
      END_STATE();
    case 402:
      if (lookahead == 'n') ADVANCE(783);
      END_STATE();
    case 403:
      if (lookahead == 'n') ADVANCE(780);
      END_STATE();
    case 404:
      if (lookahead == 'n') ADVANCE(804);
      END_STATE();
    case 405:
      if (lookahead == 'n') ADVANCE(172);
      if (lookahead == 'q') ADVANCE(705);
      END_STATE();
    case 406:
      if (lookahead == 'n') ADVANCE(300);
      END_STATE();
    case 407:
      if (lookahead == 'n') ADVANCE(301);
      END_STATE();
    case 408:
      if (lookahead == 'n') ADVANCE(655);
      END_STATE();
    case 409:
      if (lookahead == 'n') ADVANCE(304);
      END_STATE();
    case 410:
      if (lookahead == 'n') ADVANCE(449);
      END_STATE();
    case 411:
      if (lookahead == 'n') ADVANCE(182);
      END_STATE();
    case 412:
      if (lookahead == 'n') ADVANCE(102);
      END_STATE();
    case 413:
      if (lookahead == 'n') ADVANCE(558);
      END_STATE();
    case 414:
      if (lookahead == 'n') ADVANCE(125);
      END_STATE();
    case 415:
      if (lookahead == 'n') ADVANCE(66);
      END_STATE();
    case 416:
      if (lookahead == 'n') ADVANCE(162);
      END_STATE();
    case 417:
      if (lookahead == 'n') ADVANCE(621);
      END_STATE();
    case 418:
      if (lookahead == 'n') ADVANCE(247);
      END_STATE();
    case 419:
      if (lookahead == 'n') ADVANCE(71);
      END_STATE();
    case 420:
      if (lookahead == 'n') ADVANCE(33);
      END_STATE();
    case 421:
      if (lookahead == 'n') ADVANCE(58);
      END_STATE();
    case 422:
      if (lookahead == 'n') ADVANCE(629);
      END_STATE();
    case 423:
      if (lookahead == 'n') ADVANCE(643);
      if (lookahead == 'u') ADVANCE(432);
      END_STATE();
    case 424:
      if (lookahead == 'n') ADVANCE(75);
      END_STATE();
    case 425:
      if (lookahead == 'n') ADVANCE(604);
      END_STATE();
    case 426:
      if (lookahead == 'n') ADVANCE(628);
      END_STATE();
    case 427:
      if (lookahead == 'n') ADVANCE(605);
      END_STATE();
    case 428:
      if (lookahead == 'n') ADVANCE(613);
      END_STATE();
    case 429:
      if (lookahead == 'n') ADVANCE(636);
      END_STATE();
    case 430:
      if (lookahead == 'n') ADVANCE(215);
      END_STATE();
    case 431:
      if (lookahead == 'n') ADVANCE(132);
      if (lookahead == 't') ADVANCE(523);
      if (lookahead == 'v') ADVANCE(113);
      END_STATE();
    case 432:
      if (lookahead == 'n') ADVANCE(632);
      END_STATE();
    case 433:
      if (lookahead == 'n') ADVANCE(279);
      END_STATE();
    case 434:
      if (lookahead == 'n') ADVANCE(157);
      END_STATE();
    case 435:
      if (lookahead == 'n') ADVANCE(352);
      END_STATE();
    case 436:
      if (lookahead == 'n') ADVANCE(133);
      END_STATE();
    case 437:
      if (lookahead == 'n') ADVANCE(88);
      END_STATE();
    case 438:
      if (lookahead == 'o') ADVANCE(63);
      END_STATE();
    case 439:
      if (lookahead == 'o') ADVANCE(63);
      if (lookahead == 'r') ADVANCE(652);
      END_STATE();
    case 440:
      if (lookahead == 'o') ADVANCE(361);
      if (lookahead == 'w') ADVANCE(220);
      END_STATE();
    case 441:
      if (lookahead == 'o') ADVANCE(673);
      END_STATE();
    case 442:
      if (lookahead == 'o') ADVANCE(423);
      END_STATE();
    case 443:
      if (lookahead == 'o') ADVANCE(510);
      END_STATE();
    case 444:
      if (lookahead == 'o') ADVANCE(683);
      END_STATE();
    case 445:
      if (lookahead == 'o') ADVANCE(388);
      END_STATE();
    case 446:
      if (lookahead == 'o') ADVANCE(363);
      END_STATE();
    case 447:
      if (lookahead == 'o') ADVANCE(362);
      END_STATE();
    case 448:
      if (lookahead == 'o') ADVANCE(345);
      END_STATE();
    case 449:
      if (lookahead == 'o') ADVANCE(401);
      END_STATE();
    case 450:
      if (lookahead == 'o') ADVANCE(614);
      END_STATE();
    case 451:
      if (lookahead == 'o') ADVANCE(516);
      END_STATE();
    case 452:
      if (lookahead == 'o') ADVANCE(618);
      END_STATE();
    case 453:
      if (lookahead == 'o') ADVANCE(446);
      END_STATE();
    case 454:
      if (lookahead == 'o') ADVANCE(175);
      END_STATE();
    case 455:
      if (lookahead == 'o') ADVANCE(554);
      END_STATE();
    case 456:
      if (lookahead == 'o') ADVANCE(83);
      END_STATE();
    case 457:
      if (lookahead == 'o') ADVANCE(437);
      END_STATE();
    case 458:
      if (lookahead == 'o') ADVANCE(403);
      END_STATE();
    case 459:
      if (lookahead == 'o') ADVANCE(404);
      END_STATE();
    case 460:
      if (lookahead == 'o') ADVANCE(603);
      END_STATE();
    case 461:
      if (lookahead == 'o') ADVANCE(420);
      END_STATE();
    case 462:
      if (lookahead == 'o') ADVANCE(515);
      END_STATE();
    case 463:
      if (lookahead == 'o') ADVANCE(607);
      END_STATE();
    case 464:
      if (lookahead == 'o') ADVANCE(544);
      END_STATE();
    case 465:
      if (lookahead == 'o') ADVANCE(572);
      END_STATE();
    case 466:
      if (lookahead == 'o') ADVANCE(184);
      END_STATE();
    case 467:
      if (lookahead == 'o') ADVANCE(498);
      END_STATE();
    case 468:
      if (lookahead == 'o') ADVANCE(579);
      END_STATE();
    case 469:
      if (lookahead == 'o') ADVANCE(430);
      END_STATE();
    case 470:
      if (lookahead == 'o') ADVANCE(421);
      END_STATE();
    case 471:
      if (lookahead == 'o') ADVANCE(581);
      END_STATE();
    case 472:
      if (lookahead == 'o') ADVANCE(188);
      END_STATE();
    case 473:
      if (lookahead == 'o') ADVANCE(189);
      END_STATE();
    case 474:
      if (lookahead == 'o') ADVANCE(542);
      END_STATE();
    case 475:
      if (lookahead == 'o') ADVANCE(543);
      END_STATE();
    case 476:
      if (lookahead == 'o') ADVANCE(191);
      END_STATE();
    case 477:
      if (lookahead == 'o') ADVANCE(192);
      END_STATE();
    case 478:
      if (lookahead == 'o') ADVANCE(547);
      END_STATE();
    case 479:
      if (lookahead == 'o') ADVANCE(365);
      END_STATE();
    case 480:
      if (lookahead == 'o') ADVANCE(355);
      END_STATE();
    case 481:
      if (lookahead == 'o') ADVANCE(479);
      END_STATE();
    case 482:
      if (lookahead == 'o') ADVANCE(86);
      END_STATE();
    case 483:
      if (lookahead == 'o') ADVANCE(87);
      END_STATE();
    case 484:
      if (lookahead == 'o') ADVANCE(651);
      END_STATE();
    case 485:
      if (lookahead == 'p') ADVANCE(499);
      if (lookahead == 'r') ADVANCE(367);
      if (lookahead == 'u') ADVANCE(328);
      END_STATE();
    case 486:
      if (lookahead == 'p') ADVANCE(770);
      END_STATE();
    case 487:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 488:
      if (lookahead == 'p') ADVANCE(400);
      END_STATE();
    case 489:
      if (lookahead == 'p') ADVANCE(7);
      END_STATE();
    case 490:
      if (lookahead == 'p') ADVANCE(371);
      END_STATE();
    case 491:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 492:
      if (lookahead == 'p') ADVANCE(42);
      END_STATE();
    case 493:
      if (lookahead == 'p') ADVANCE(55);
      END_STATE();
    case 494:
      if (lookahead == 'p') ADVANCE(228);
      END_STATE();
    case 495:
      if (lookahead == 'p') ADVANCE(528);
      END_STATE();
    case 496:
      if (lookahead == 'p') ADVANCE(13);
      END_STATE();
    case 497:
      if (lookahead == 'p') ADVANCE(21);
      END_STATE();
    case 498:
      if (lookahead == 'p') ADVANCE(267);
      END_STATE();
    case 499:
      if (lookahead == 'p') ADVANCE(225);
      END_STATE();
    case 500:
      if (lookahead == 'p') ADVANCE(120);
      END_STATE();
    case 501:
      if (lookahead == 'p') ADVANCE(637);
      END_STATE();
    case 502:
      if (lookahead == 'p') ADVANCE(122);
      if (lookahead == 'q') ADVANCE(666);
      END_STATE();
    case 503:
      if (lookahead == 'p') ADVANCE(123);
      if (lookahead == 'q') ADVANCE(667);
      END_STATE();
    case 504:
      if (lookahead == 'p') ADVANCE(589);
      END_STATE();
    case 505:
      if (lookahead == 'p') ADVANCE(44);
      END_STATE();
    case 506:
      if (lookahead == 'q') ADVANCE(705);
      END_STATE();
    case 507:
      if (lookahead == 'q') ADVANCE(372);
      END_STATE();
    case 508:
      if (lookahead == 'q') ADVANCE(668);
      END_STATE();
    case 509:
      if (lookahead == 'r') ADVANCE(700);
      END_STATE();
    case 510:
      if (lookahead == 'r') ADVANCE(698);
      END_STATE();
    case 511:
      if (lookahead == 'r') ADVANCE(728);
      END_STATE();
    case 512:
      if (lookahead == 'r') ADVANCE(733);
      END_STATE();
    case 513:
      if (lookahead == 'r') ADVANCE(750);
      END_STATE();
    case 514:
      if (lookahead == 'r') ADVANCE(773);
      END_STATE();
    case 515:
      if (lookahead == 'r') ADVANCE(781);
      END_STATE();
    case 516:
      if (lookahead == 'r') ADVANCE(364);
      END_STATE();
    case 517:
      if (lookahead == 'r') ADVANCE(143);
      END_STATE();
    case 518:
      if (lookahead == 'r') ADVANCE(676);
      END_STATE();
    case 519:
      if (lookahead == 'r') ADVANCE(685);
      END_STATE();
    case 520:
      if (lookahead == 'r') ADVANCE(648);
      END_STATE();
    case 521:
      if (lookahead == 'r') ADVANCE(686);
      END_STATE();
    case 522:
      if (lookahead == 'r') ADVANCE(687);
      END_STATE();
    case 523:
      if (lookahead == 'r') ADVANCE(659);
      END_STATE();
    case 524:
      if (lookahead == 'r') ADVANCE(323);
      END_STATE();
    case 525:
      if (lookahead == 'r') ADVANCE(40);
      END_STATE();
    case 526:
      if (lookahead == 'r') ADVANCE(82);
      END_STATE();
    case 527:
      if (lookahead == 'r') ADVANCE(272);
      END_STATE();
    case 528:
      if (lookahead == 'r') ADVANCE(444);
      END_STATE();
    case 529:
      if (lookahead == 'r') ADVANCE(456);
      END_STATE();
    case 530:
      if (lookahead == 'r') ADVANCE(325);
      END_STATE();
    case 531:
      if (lookahead == 'r') ADVANCE(576);
      END_STATE();
    case 532:
      if (lookahead == 'r') ADVANCE(222);
      END_STATE();
    case 533:
      if (lookahead == 'r') ADVANCE(152);
      END_STATE();
    case 534:
      if (lookahead == 'r') ADVANCE(57);
      END_STATE();
    case 535:
      if (lookahead == 'r') ADVANCE(326);
      END_STATE();
    case 536:
      if (lookahead == 'r') ADVANCE(467);
      END_STATE();
    case 537:
      if (lookahead == 'r') ADVANCE(329);
      END_STATE();
    case 538:
      if (lookahead == 'r') ADVANCE(562);
      END_STATE();
    case 539:
      if (lookahead == 'r') ADVANCE(327);
      END_STATE();
    case 540:
      if (lookahead == 'r') ADVANCE(203);
      END_STATE();
    case 541:
      if (lookahead == 'r') ADVANCE(207);
      END_STATE();
    case 542:
      if (lookahead == 'r') ADVANCE(208);
      END_STATE();
    case 543:
      if (lookahead == 'r') ADVANCE(210);
      END_STATE();
    case 544:
      if (lookahead == 'r') ADVANCE(606);
      END_STATE();
    case 545:
      if (lookahead == 'r') ADVANCE(633);
      END_STATE();
    case 546:
      if (lookahead == 'r') ADVANCE(243);
      END_STATE();
    case 547:
      if (lookahead == 'r') ADVANCE(214);
      END_STATE();
    case 548:
      if (lookahead == 'r') ADVANCE(224);
      if (lookahead == 'v') ADVANCE(284);
      END_STATE();
    case 549:
      if (lookahead == 'r') ADVANCE(334);
      END_STATE();
    case 550:
      if (lookahead == 'r') ADVANCE(154);
      if (lookahead == 's') ADVANCE(507);
      if (lookahead == 'x') ADVANCE(578);
      END_STATE();
    case 551:
      if (lookahead == 'r') ADVANCE(187);
      END_STATE();
    case 552:
      if (lookahead == 'r') ADVANCE(338);
      END_STATE();
    case 553:
      if (lookahead == 'r') ADVANCE(252);
      END_STATE();
    case 554:
      if (lookahead == 'r') ADVANCE(680);
      END_STATE();
    case 555:
      if (lookahead == 'r') ADVANCE(356);
      END_STATE();
    case 556:
      if (lookahead == 's') ADVANCE(750);
      END_STATE();
    case 557:
      if (lookahead == 's') ADVANCE(719);
      END_STATE();
    case 558:
      if (lookahead == 's') ADVANCE(718);
      END_STATE();
    case 559:
      if (lookahead == 's') ADVANCE(730);
      END_STATE();
    case 560:
      if (lookahead == 's') ADVANCE(767);
      END_STATE();
    case 561:
      if (lookahead == 's') ADVANCE(799);
      END_STATE();
    case 562:
      if (lookahead == 's') ADVANCE(800);
      END_STATE();
    case 563:
      if (lookahead == 's') ADVANCE(801);
      END_STATE();
    case 564:
      if (lookahead == 's') ADVANCE(802);
      END_STATE();
    case 565:
      if (lookahead == 's') ADVANCE(803);
      END_STATE();
    case 566:
      if (lookahead == 's') ADVANCE(366);
      if (lookahead == 't') ADVANCE(100);
      END_STATE();
    case 567:
      if (lookahead == 's') ADVANCE(60);
      END_STATE();
    case 568:
      if (lookahead == 's') ADVANCE(202);
      END_STATE();
    case 569:
      if (lookahead == 's') ADVANCE(160);
      END_STATE();
    case 570:
      if (lookahead == 's') ADVANCE(620);
      END_STATE();
    case 571:
      if (lookahead == 's') ADVANCE(64);
      END_STATE();
    case 572:
      if (lookahead == 's') ADVANCE(623);
      END_STATE();
    case 573:
      if (lookahead == 's') ADVANCE(315);
      END_STATE();
    case 574:
      if (lookahead == 's') ADVANCE(457);
      END_STATE();
    case 575:
      if (lookahead == 's') ADVANCE(76);
      END_STATE();
    case 576:
      if (lookahead == 's') ADVANCE(350);
      END_STATE();
    case 577:
      if (lookahead == 's') ADVANCE(339);
      END_STATE();
    case 578:
      if (lookahead == 's') ADVANCE(560);
      END_STATE();
    case 579:
      if (lookahead == 's') ADVANCE(601);
      END_STATE();
    case 580:
      if (lookahead == 's') ADVANCE(408);
      END_STATE();
    case 581:
      if (lookahead == 's') ADVANCE(640);
      END_STATE();
    case 582:
      if (lookahead == 's') ADVANCE(625);
      END_STATE();
    case 583:
      if (lookahead == 's') ADVANCE(263);
      END_STATE();
    case 584:
      if (lookahead == 's') ADVANCE(626);
      END_STATE();
    case 585:
      if (lookahead == 's') ADVANCE(630);
      END_STATE();
    case 586:
      if (lookahead == 's') ADVANCE(635);
      END_STATE();
    case 587:
      if (lookahead == 's') ADVANCE(245);
      END_STATE();
    case 588:
      if (lookahead == 's') ADVANCE(253);
      END_STATE();
    case 589:
      if (lookahead == 's') ADVANCE(644);
      END_STATE();
    case 590:
      if (lookahead == 's') ADVANCE(237);
      END_STATE();
    case 591:
      if (lookahead == 's') ADVANCE(588);
      END_STATE();
    case 592:
      if (lookahead == 's') ADVANCE(248);
      END_STATE();
    case 593:
      if (lookahead == 's') ADVANCE(79);
      END_STATE();
    case 594:
      if (lookahead == 's') ADVANCE(166);
      END_STATE();
    case 595:
      if (lookahead == 's') ADVANCE(646);
      END_STATE();
    case 596:
      if (lookahead == 's') ADVANCE(482);
      END_STATE();
    case 597:
      if (lookahead == 's') ADVANCE(483);
      END_STATE();
    case 598:
      if (lookahead == 't') ADVANCE(142);
      END_STATE();
    case 599:
      if (lookahead == 't') ADVANCE(755);
      END_STATE();
    case 600:
      if (lookahead == 't') ADVANCE(721);
      END_STATE();
    case 601:
      if (lookahead == 't') ADVANCE(772);
      END_STATE();
    case 602:
      if (lookahead == 't') ADVANCE(782);
      END_STATE();
    case 603:
      if (lookahead == 't') ADVANCE(808);
      END_STATE();
    case 604:
      if (lookahead == 't') ADVANCE(779);
      END_STATE();
    case 605:
      if (lookahead == 't') ADVANCE(787);
      END_STATE();
    case 606:
      if (lookahead == 't') ADVANCE(763);
      END_STATE();
    case 607:
      if (lookahead == 't') ADVANCE(806);
      END_STATE();
    case 608:
      if (lookahead == 't') ADVANCE(609);
      END_STATE();
    case 609:
      if (lookahead == 't') ADVANCE(489);
      END_STATE();
    case 610:
      if (lookahead == 't') ADVANCE(311);
      END_STATE();
    case 611:
      if (lookahead == 't') ADVANCE(684);
      END_STATE();
    case 612:
      if (lookahead == 't') ADVANCE(312);
      END_STATE();
    case 613:
      if (lookahead == 't') ADVANCE(101);
      END_STATE();
    case 614:
      if (lookahead == 't') ADVANCE(54);
      END_STATE();
    case 615:
      if (lookahead == 't') ADVANCE(318);
      END_STATE();
    case 616:
      if (lookahead == 't') ADVANCE(149);
      END_STATE();
    case 617:
      if (lookahead == 't') ADVANCE(319);
      END_STATE();
    case 618:
      if (lookahead == 't') ADVANCE(418);
      END_STATE();
    case 619:
      if (lookahead == 't') ADVANCE(313);
      END_STATE();
    case 620:
      if (lookahead == 't') ADVANCE(549);
      END_STATE();
    case 621:
      if (lookahead == 't') ADVANCE(25);
      END_STATE();
    case 622:
      if (lookahead == 't') ADVANCE(314);
      END_STATE();
    case 623:
      if (lookahead == 't') ADVANCE(412);
      END_STATE();
    case 624:
      if (lookahead == 't') ADVANCE(111);
      END_STATE();
    case 625:
      if (lookahead == 't') ADVANCE(10);
      END_STATE();
    case 626:
      if (lookahead == 't') ADVANCE(11);
      END_STATE();
    case 627:
      if (lookahead == 't') ADVANCE(97);
      END_STATE();
    case 628:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 629:
      if (lookahead == 't') ADVANCE(68);
      END_STATE();
    case 630:
      if (lookahead == 't') ADVANCE(107);
      END_STATE();
    case 631:
      if (lookahead == 't') ADVANCE(529);
      END_STATE();
    case 632:
      if (lookahead == 't') ADVANCE(519);
      END_STATE();
    case 633:
      if (lookahead == 't') ADVANCE(59);
      END_STATE();
    case 634:
      if (lookahead == 't') ADVANCE(235);
      END_STATE();
    case 635:
      if (lookahead == 't') ADVANCE(22);
      END_STATE();
    case 636:
      if (lookahead == 't') ADVANCE(24);
      END_STATE();
    case 637:
      if (lookahead == 't') ADVANCE(244);
      END_STATE();
    case 638:
      if (lookahead == 't') ADVANCE(236);
      END_STATE();
    case 639:
      if (lookahead == 't') ADVANCE(246);
      END_STATE();
    case 640:
      if (lookahead == 't') ADVANCE(106);
      END_STATE();
    case 641:
      if (lookahead == 't') ADVANCE(84);
      END_STATE();
    case 642:
      if (lookahead == 't') ADVANCE(492);
      END_STATE();
    case 643:
      if (lookahead == 't') ADVANCE(346);
      END_STATE();
    case 644:
      if (lookahead == 't') ADVANCE(546);
      END_STATE();
    case 645:
      if (lookahead == 't') ADVANCE(642);
      END_STATE();
    case 646:
      if (lookahead == 't') ADVANCE(552);
      END_STATE();
    case 647:
      if (lookahead == 't') ADVANCE(354);
      END_STATE();
    case 648:
      if (lookahead == 't') ADVANCE(593);
      END_STATE();
    case 649:
      if (lookahead == 't') ADVANCE(505);
      END_STATE();
    case 650:
      if (lookahead == 't') ADVANCE(649);
      END_STATE();
    case 651:
      if (lookahead == 't') ADVANCE(89);
      END_STATE();
    case 652:
      if (lookahead == 'u') ADVANCE(201);
      END_STATE();
    case 653:
      if (lookahead == 'u') ADVANCE(138);
      END_STATE();
    case 654:
      if (lookahead == 'u') ADVANCE(493);
      END_STATE();
    case 655:
      if (lookahead == 'u') ADVANCE(381);
      END_STATE();
    case 656:
      if (lookahead == 'u') ADVANCE(504);
      END_STATE();
    case 657:
      if (lookahead == 'u') ADVANCE(374);
      END_STATE();
    case 658:
      if (lookahead == 'u') ADVANCE(278);
      END_STATE();
    case 659:
      if (lookahead == 'u') ADVANCE(416);
      END_STATE();
    case 660:
      if (lookahead == 'u') ADVANCE(435);
      END_STATE();
    case 661:
      if (lookahead == 'u') ADVANCE(536);
      END_STATE();
    case 662:
      if (lookahead == 'u') ADVANCE(535);
      END_STATE();
    case 663:
      if (lookahead == 'u') ADVANCE(617);
      END_STATE();
    case 664:
      if (lookahead == 'u') ADVANCE(539);
      END_STATE();
    case 665:
      if (lookahead == 'u') ADVANCE(256);
      END_STATE();
    case 666:
      if (lookahead == 'u') ADVANCE(265);
      END_STATE();
    case 667:
      if (lookahead == 'u') ADVANCE(266);
      END_STATE();
    case 668:
      if (lookahead == 'u') ADVANCE(280);
      END_STATE();
    case 669:
      if (lookahead == 'u') ADVANCE(129);
      END_STATE();
    case 670:
      if (lookahead == 'u') ADVANCE(283);
      END_STATE();
    case 671:
      if (lookahead == 'u') ADVANCE(379);
      END_STATE();
    case 672:
      if (lookahead == 'v') ADVANCE(50);
      END_STATE();
    case 673:
      if (lookahead == 'v') ADVANCE(232);
      END_STATE();
    case 674:
      if (lookahead == 'v') ADVANCE(336);
      END_STATE();
    case 675:
      if (lookahead == 'v') ADVANCE(447);
      END_STATE();
    case 676:
      if (lookahead == 'v') ADVANCE(270);
      END_STATE();
    case 677:
      if (lookahead == 'w') ADVANCE(23);
      END_STATE();
    case 678:
      if (lookahead == 'w') ADVANCE(335);
      END_STATE();
    case 679:
      if (lookahead == 'w') ADVANCE(128);
      END_STATE();
    case 680:
      if (lookahead == 'w') ADVANCE(117);
      END_STATE();
    case 681:
      if (lookahead == 'w') ADVANCE(340);
      END_STATE();
    case 682:
      if (lookahead == 'x') ADVANCE(73);
      END_STATE();
    case 683:
      if (lookahead == 'x') ADVANCE(342);
      END_STATE();
    case 684:
      if (lookahead == 'y') ADVANCE(784);
      END_STATE();
    case 685:
      if (lookahead == 'y') ADVANCE(788);
      END_STATE();
    case 686:
      if (lookahead == 'y') ADVANCE(778);
      END_STATE();
    case 687:
      if (lookahead == 'y') ADVANCE(794);
      END_STATE();
    case 688:
      if (lookahead == 'y') ADVANCE(383);
      END_STATE();
    case 689:
      if (lookahead == 'y') ADVANCE(634);
      END_STATE();
    case 690:
      if (lookahead == 'z') ADVANCE(469);
      END_STATE();
    case 691:
      if (lookahead == 'z') ADVANCE(254);
      END_STATE();
    case 692:
      if (lookahead == '|') ADVANCE(701);
      END_STATE();
    case 693:
      if (eof) ADVANCE(694);
      if (lookahead == '!') ADVANCE(756);
      if (lookahead == '#') ADVANCE(704);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(722);
      if (lookahead == ')') ADVANCE(724);
      if (lookahead == '/') ADVANCE(746);
      if (lookahead == '2') ADVANCE(15);
      if (lookahead == '=') ADVANCE(52);
      if (lookahead == '^') ADVANCE(53);
      if (lookahead == 'a') ADVANCE(395);
      if (lookahead == 'c') ADVANCE(291);
      if (lookahead == 'e') ADVANCE(405);
      if (lookahead == 'h') ADVANCE(608);
      if (lookahead == 'i') ADVANCE(487);
      if (lookahead == 'l') ADVANCE(259);
      if (lookahead == 'n') ADVANCE(199);
      if (lookahead == 'o') ADVANCE(509);
      if (lookahead == 'r') ADVANCE(93);
      if (lookahead == 's') ADVANCE(566);
      if (lookahead == 't') ADVANCE(438);
      if (lookahead == 'u') ADVANCE(485);
      if (lookahead == 'x') ADVANCE(443);
      if (lookahead == '|') ADVANCE(692);
      if (lookahead == '}') ADVANCE(703);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(17);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(693)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(18);
      END_STATE();
    case 694:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 695:
      ACCEPT_TOKEN(anon_sym_in);
      END_STATE();
    case 696:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 697:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 698:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 699:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 700:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 701:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 702:
      ACCEPT_TOKEN(anon_sym_LBRACE);
      END_STATE();
    case 703:
      ACCEPT_TOKEN(anon_sym_RBRACE);
      END_STATE();
    case 704:
      ACCEPT_TOKEN(sym_comment);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(704);
      END_STATE();
    case 705:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 706:
      ACCEPT_TOKEN(anon_sym_ne);
      END_STATE();
    case 707:
      ACCEPT_TOKEN(anon_sym_lt);
      END_STATE();
    case 708:
      ACCEPT_TOKEN(anon_sym_le);
      END_STATE();
    case 709:
      ACCEPT_TOKEN(anon_sym_le);
      if (lookahead == 'n') ADVANCE(726);
      END_STATE();
    case 710:
      ACCEPT_TOKEN(anon_sym_gt);
      END_STATE();
    case 711:
      ACCEPT_TOKEN(anon_sym_ge);
      END_STATE();
    case 712:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 713:
      ACCEPT_TOKEN(anon_sym_BANG_EQ);
      END_STATE();
    case 714:
      ACCEPT_TOKEN(anon_sym_LT);
      if (lookahead == '=') ADVANCE(715);
      END_STATE();
    case 715:
      ACCEPT_TOKEN(anon_sym_LT_EQ);
      END_STATE();
    case 716:
      ACCEPT_TOKEN(anon_sym_GT);
      if (lookahead == '=') ADVANCE(717);
      END_STATE();
    case 717:
      ACCEPT_TOKEN(anon_sym_GT_EQ);
      END_STATE();
    case 718:
      ACCEPT_TOKEN(anon_sym_contains);
      END_STATE();
    case 719:
      ACCEPT_TOKEN(anon_sym_matches);
      END_STATE();
    case 720:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 721:
      ACCEPT_TOKEN(anon_sym_concat);
      END_STATE();
    case 722:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 723:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 724:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 725:
      ACCEPT_TOKEN(anon_sym_ends_with);
      END_STATE();
    case 726:
      ACCEPT_TOKEN(anon_sym_len);
      END_STATE();
    case 727:
      ACCEPT_TOKEN(anon_sym_lookup_json_string);
      END_STATE();
    case 728:
      ACCEPT_TOKEN(anon_sym_lower);
      END_STATE();
    case 729:
      ACCEPT_TOKEN(anon_sym_regex_replace);
      END_STATE();
    case 730:
      ACCEPT_TOKEN(anon_sym_remove_bytes);
      END_STATE();
    case 731:
      ACCEPT_TOKEN(anon_sym_starts_with);
      END_STATE();
    case 732:
      ACCEPT_TOKEN(anon_sym_to_string);
      END_STATE();
    case 733:
      ACCEPT_TOKEN(anon_sym_upper);
      END_STATE();
    case 734:
      ACCEPT_TOKEN(anon_sym_url_decode);
      END_STATE();
    case 735:
      ACCEPT_TOKEN(anon_sym_uuidv4);
      END_STATE();
    case 736:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(737);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(737);
      END_STATE();
    case 737:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(737);
      END_STATE();
    case 738:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 739:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 740:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 741:
      ACCEPT_TOKEN(sym_ipv4);
      END_STATE();
    case 742:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '5') ADVANCE(743);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(741);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(744);
      END_STATE();
    case 743:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(741);
      END_STATE();
    case 744:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(741);
      END_STATE();
    case 745:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(744);
      END_STATE();
    case 746:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 747:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      END_STATE();
    case 748:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(747);
      END_STATE();
    case 749:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(747);
      END_STATE();
    case 750:
      ACCEPT_TOKEN(sym_ip_list);
      END_STATE();
    case 751:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == '.') ADVANCE(98);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(754);
      END_STATE();
    case 752:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'c') ADVANCE(753);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(754);
      END_STATE();
    case 753:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'f') ADVANCE(751);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(754);
      END_STATE();
    case 754:
      ACCEPT_TOKEN(sym_ip_list);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(754);
      END_STATE();
    case 755:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 756:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(713);
      END_STATE();
    case 757:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 758:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 759:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 760:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 761:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 762:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 763:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 764:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 765:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(550);
      END_STATE();
    case 766:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 767:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 768:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 769:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(159);
      END_STATE();
    case 770:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 771:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 772:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 773:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 774:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 775:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 776:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(502);
      END_STATE();
    case 777:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 778:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 779:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 780:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 781:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 782:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 783:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 784:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 785:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 786:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 787:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 788:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 789:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 790:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 791:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 792:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(503);
      END_STATE();
    case 793:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 794:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 795:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 796:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 797:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 798:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 799:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 800:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(431);
      END_STATE();
    case 801:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTnames);
      END_STATE();
    case 802:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTvalues);
      END_STATE();
    case 803:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTaccepted_languages);
      END_STATE();
    case 804:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 805:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 806:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 807:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 808:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 809:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 810:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_verified);
      END_STATE();
    case 811:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTtruncated);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 693},
  [2] = {.lex_state = 693},
  [3] = {.lex_state = 693},
  [4] = {.lex_state = 693},
  [5] = {.lex_state = 693},
  [6] = {.lex_state = 693},
  [7] = {.lex_state = 693},
  [8] = {.lex_state = 693},
  [9] = {.lex_state = 693},
  [10] = {.lex_state = 693},
  [11] = {.lex_state = 693},
  [12] = {.lex_state = 693},
  [13] = {.lex_state = 693},
  [14] = {.lex_state = 693},
  [15] = {.lex_state = 693},
  [16] = {.lex_state = 693},
  [17] = {.lex_state = 693},
  [18] = {.lex_state = 693},
  [19] = {.lex_state = 693},
  [20] = {.lex_state = 693},
  [21] = {.lex_state = 693},
  [22] = {.lex_state = 693},
  [23] = {.lex_state = 693},
  [24] = {.lex_state = 693},
  [25] = {.lex_state = 693},
  [26] = {.lex_state = 693},
  [27] = {.lex_state = 693},
  [28] = {.lex_state = 693},
  [29] = {.lex_state = 693},
  [30] = {.lex_state = 693},
  [31] = {.lex_state = 693},
  [32] = {.lex_state = 693},
  [33] = {.lex_state = 693},
  [34] = {.lex_state = 693},
  [35] = {.lex_state = 693},
  [36] = {.lex_state = 693},
  [37] = {.lex_state = 693},
  [38] = {.lex_state = 693},
  [39] = {.lex_state = 693},
  [40] = {.lex_state = 693},
  [41] = {.lex_state = 693},
  [42] = {.lex_state = 693},
  [43] = {.lex_state = 693},
  [44] = {.lex_state = 693},
  [45] = {.lex_state = 1},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 0},
  [48] = {.lex_state = 0},
  [49] = {.lex_state = 0},
  [50] = {.lex_state = 0},
  [51] = {.lex_state = 0},
  [52] = {.lex_state = 0},
  [53] = {.lex_state = 0},
  [54] = {.lex_state = 0},
  [55] = {.lex_state = 0},
  [56] = {.lex_state = 0},
  [57] = {.lex_state = 0},
  [58] = {.lex_state = 0},
  [59] = {.lex_state = 0},
  [60] = {.lex_state = 0},
  [61] = {.lex_state = 0},
  [62] = {.lex_state = 1},
  [63] = {.lex_state = 1},
  [64] = {.lex_state = 1},
  [65] = {.lex_state = 1},
  [66] = {.lex_state = 1},
  [67] = {.lex_state = 1},
  [68] = {.lex_state = 1},
  [69] = {.lex_state = 1},
  [70] = {.lex_state = 1},
  [71] = {.lex_state = 1},
  [72] = {.lex_state = 1},
  [73] = {.lex_state = 1},
  [74] = {.lex_state = 1},
  [75] = {.lex_state = 1},
  [76] = {.lex_state = 1},
  [77] = {.lex_state = 1},
  [78] = {.lex_state = 1},
  [79] = {.lex_state = 1},
  [80] = {.lex_state = 0},
  [81] = {.lex_state = 0},
  [82] = {.lex_state = 693},
  [83] = {.lex_state = 0},
  [84] = {.lex_state = 693},
  [85] = {.lex_state = 1},
  [86] = {.lex_state = 1},
  [87] = {.lex_state = 1},
  [88] = {.lex_state = 693},
  [89] = {.lex_state = 0},
  [90] = {.lex_state = 693},
  [91] = {.lex_state = 0},
  [92] = {.lex_state = 1},
  [93] = {.lex_state = 1},
  [94] = {.lex_state = 0},
  [95] = {.lex_state = 0},
  [96] = {.lex_state = 1},
  [97] = {.lex_state = 1},
  [98] = {.lex_state = 1},
  [99] = {.lex_state = 0},
  [100] = {.lex_state = 0},
  [101] = {.lex_state = 0},
  [102] = {.lex_state = 0},
  [103] = {.lex_state = 0},
  [104] = {.lex_state = 0},
  [105] = {.lex_state = 3},
  [106] = {.lex_state = 0},
  [107] = {.lex_state = 0},
  [108] = {.lex_state = 0},
  [109] = {.lex_state = 0},
  [110] = {.lex_state = 0},
  [111] = {.lex_state = 0},
  [112] = {.lex_state = 0},
  [113] = {.lex_state = 0},
  [114] = {.lex_state = 0},
  [115] = {.lex_state = 0},
  [116] = {.lex_state = 0},
  [117] = {.lex_state = 0},
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
  [128] = {.lex_state = 0},
  [129] = {.lex_state = 0},
  [130] = {.lex_state = 1},
  [131] = {.lex_state = 0},
  [132] = {.lex_state = 0},
  [133] = {.lex_state = 0},
  [134] = {.lex_state = 0},
  [135] = {.lex_state = 1},
  [136] = {.lex_state = 0},
  [137] = {.lex_state = 0},
  [138] = {.lex_state = 0},
  [139] = {.lex_state = 0},
  [140] = {.lex_state = 0},
  [141] = {.lex_state = 0},
  [142] = {.lex_state = 0},
  [143] = {.lex_state = 0},
  [144] = {.lex_state = 0},
  [145] = {.lex_state = 0},
  [146] = {.lex_state = 0},
  [147] = {.lex_state = 0},
  [148] = {.lex_state = 0},
  [149] = {.lex_state = 0},
  [150] = {.lex_state = 0},
  [151] = {.lex_state = 0},
  [152] = {.lex_state = 0},
  [153] = {.lex_state = 0},
  [154] = {.lex_state = 1},
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
  [165] = {.lex_state = 0},
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
    [anon_sym_LBRACK] = ACTIONS(1),
    [anon_sym_RBRACK] = ACTIONS(1),
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
    [sym_source_file] = STATE(142),
    [sym__expression] = STATE(43),
    [sym_not_expression] = STATE(43),
    [sym_in_expression] = STATE(43),
    [sym_compound_expression] = STATE(43),
    [sym_simple_expression] = STATE(43),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(43),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
    [aux_sym_source_file_repeat1] = STATE(2),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
  },
  [2] = {
    [sym__expression] = STATE(43),
    [sym_not_expression] = STATE(43),
    [sym_in_expression] = STATE(43),
    [sym_compound_expression] = STATE(43),
    [sym_simple_expression] = STATE(43),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(43),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(55),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
  },
  [3] = {
    [sym__expression] = STATE(43),
    [sym_not_expression] = STATE(43),
    [sym_in_expression] = STATE(43),
    [sym_compound_expression] = STATE(43),
    [sym_simple_expression] = STATE(43),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(43),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(57),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(59),
    [anon_sym_LPAREN] = ACTIONS(62),
    [anon_sym_ends_with] = ACTIONS(65),
    [anon_sym_len] = ACTIONS(68),
    [anon_sym_lookup_json_string] = ACTIONS(71),
    [anon_sym_lower] = ACTIONS(74),
    [anon_sym_regex_replace] = ACTIONS(77),
    [anon_sym_remove_bytes] = ACTIONS(80),
    [anon_sym_starts_with] = ACTIONS(83),
    [anon_sym_to_string] = ACTIONS(86),
    [anon_sym_upper] = ACTIONS(89),
    [anon_sym_url_decode] = ACTIONS(92),
    [anon_sym_uuidv4] = ACTIONS(95),
    [anon_sym_not] = ACTIONS(98),
    [anon_sym_BANG] = ACTIONS(98),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(101),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(101),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(101),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(101),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(101),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(101),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(101),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(101),
    [anon_sym_ip_DOTsrc] = ACTIONS(107),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(110),
    [anon_sym_http_DOTcookie] = ACTIONS(113),
    [anon_sym_http_DOThost] = ACTIONS(113),
    [anon_sym_http_DOTreferer] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(113),
    [anon_sym_http_DOTuser_agent] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(113),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(113),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(113),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(113),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(113),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(113),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(113),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(113),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(113),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(113),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(113),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(113),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(116),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(113),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(113),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(113),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(113),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(113),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(119),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(122),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(125),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(125),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(125),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(128),
    [anon_sym_ssl] = ACTIONS(128),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(128),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(128),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(128),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(128),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(128),
  },
  [4] = {
    [sym__expression] = STATE(18),
    [sym_not_expression] = STATE(18),
    [sym_in_expression] = STATE(18),
    [sym_compound_expression] = STATE(18),
    [sym_simple_expression] = STATE(18),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(18),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
  },
  [5] = {
    [sym__expression] = STATE(80),
    [sym_not_expression] = STATE(80),
    [sym_in_expression] = STATE(80),
    [sym_compound_expression] = STATE(80),
    [sym_simple_expression] = STATE(80),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(80),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
  },
  [6] = {
    [sym__expression] = STATE(16),
    [sym_not_expression] = STATE(16),
    [sym_in_expression] = STATE(16),
    [sym_compound_expression] = STATE(16),
    [sym_simple_expression] = STATE(16),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(16),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
  },
  [7] = {
    [sym__expression] = STATE(24),
    [sym_not_expression] = STATE(24),
    [sym_in_expression] = STATE(24),
    [sym_compound_expression] = STATE(24),
    [sym_simple_expression] = STATE(24),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(24),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
  },
  [8] = {
    [sym__expression] = STATE(29),
    [sym_not_expression] = STATE(29),
    [sym_in_expression] = STATE(29),
    [sym_compound_expression] = STATE(29),
    [sym_simple_expression] = STATE(29),
    [sym__bool_lhs] = STATE(13),
    [sym__number_lhs] = STATE(77),
    [sym__string_lhs] = STATE(74),
    [sym_string_func] = STATE(74),
    [sym_number_func] = STATE(77),
    [sym_bool_func] = STATE(13),
    [sym_concat_func] = STATE(63),
    [sym_ends_with_func] = STATE(12),
    [sym_len_func] = STATE(79),
    [sym_lookup_func] = STATE(63),
    [sym_lower_func] = STATE(63),
    [sym_regex_replace_func] = STATE(63),
    [sym_remove_bytes_func] = STATE(63),
    [sym_starts_with_func] = STATE(12),
    [sym_to_string_func] = STATE(63),
    [sym_upper_func] = STATE(63),
    [sym_url_decode_func] = STATE(63),
    [sym_uuid_func] = STATE(63),
    [sym_group] = STATE(29),
    [sym_not_operator] = STATE(8),
    [sym__stringlike_field] = STATE(71),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(83),
    [sym_string_field] = STATE(71),
    [sym_map_string_array_field] = STATE(139),
    [sym_array_string_field] = STATE(138),
    [sym_bool_field] = STATE(13),
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
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
  },
  [9] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(131),
    [anon_sym_ne] = ACTIONS(131),
    [anon_sym_EQ_EQ] = ACTIONS(131),
    [anon_sym_BANG_EQ] = ACTIONS(131),
    [anon_sym_concat] = ACTIONS(131),
    [anon_sym_LPAREN] = ACTIONS(131),
    [anon_sym_RPAREN] = ACTIONS(131),
    [anon_sym_ends_with] = ACTIONS(131),
    [anon_sym_len] = ACTIONS(131),
    [anon_sym_lookup_json_string] = ACTIONS(131),
    [anon_sym_lower] = ACTIONS(131),
    [anon_sym_regex_replace] = ACTIONS(131),
    [anon_sym_remove_bytes] = ACTIONS(131),
    [anon_sym_starts_with] = ACTIONS(131),
    [anon_sym_to_string] = ACTIONS(131),
    [anon_sym_upper] = ACTIONS(131),
    [anon_sym_url_decode] = ACTIONS(131),
    [anon_sym_uuidv4] = ACTIONS(131),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(133),
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
  [10] = {
    [ts_builtin_sym_end] = ACTIONS(135),
    [anon_sym_AMP_AMP] = ACTIONS(135),
    [anon_sym_and] = ACTIONS(135),
    [anon_sym_xor] = ACTIONS(135),
    [anon_sym_CARET_CARET] = ACTIONS(135),
    [anon_sym_or] = ACTIONS(135),
    [anon_sym_PIPE_PIPE] = ACTIONS(135),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(135),
    [anon_sym_ne] = ACTIONS(135),
    [anon_sym_EQ_EQ] = ACTIONS(135),
    [anon_sym_BANG_EQ] = ACTIONS(135),
    [anon_sym_concat] = ACTIONS(135),
    [anon_sym_LPAREN] = ACTIONS(135),
    [anon_sym_RPAREN] = ACTIONS(135),
    [anon_sym_ends_with] = ACTIONS(135),
    [anon_sym_len] = ACTIONS(135),
    [anon_sym_lookup_json_string] = ACTIONS(135),
    [anon_sym_lower] = ACTIONS(135),
    [anon_sym_regex_replace] = ACTIONS(135),
    [anon_sym_remove_bytes] = ACTIONS(135),
    [anon_sym_starts_with] = ACTIONS(135),
    [anon_sym_to_string] = ACTIONS(135),
    [anon_sym_upper] = ACTIONS(135),
    [anon_sym_url_decode] = ACTIONS(135),
    [anon_sym_uuidv4] = ACTIONS(135),
    [anon_sym_not] = ACTIONS(135),
    [anon_sym_BANG] = ACTIONS(137),
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
  [11] = {
    [ts_builtin_sym_end] = ACTIONS(139),
    [anon_sym_AMP_AMP] = ACTIONS(139),
    [anon_sym_and] = ACTIONS(139),
    [anon_sym_xor] = ACTIONS(139),
    [anon_sym_CARET_CARET] = ACTIONS(139),
    [anon_sym_or] = ACTIONS(139),
    [anon_sym_PIPE_PIPE] = ACTIONS(139),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(139),
    [anon_sym_ne] = ACTIONS(139),
    [anon_sym_EQ_EQ] = ACTIONS(139),
    [anon_sym_BANG_EQ] = ACTIONS(139),
    [anon_sym_concat] = ACTIONS(139),
    [anon_sym_LPAREN] = ACTIONS(139),
    [anon_sym_RPAREN] = ACTIONS(139),
    [anon_sym_ends_with] = ACTIONS(139),
    [anon_sym_len] = ACTIONS(139),
    [anon_sym_lookup_json_string] = ACTIONS(139),
    [anon_sym_lower] = ACTIONS(139),
    [anon_sym_regex_replace] = ACTIONS(139),
    [anon_sym_remove_bytes] = ACTIONS(139),
    [anon_sym_starts_with] = ACTIONS(139),
    [anon_sym_to_string] = ACTIONS(139),
    [anon_sym_upper] = ACTIONS(139),
    [anon_sym_url_decode] = ACTIONS(139),
    [anon_sym_uuidv4] = ACTIONS(139),
    [anon_sym_not] = ACTIONS(139),
    [anon_sym_BANG] = ACTIONS(141),
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
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(143),
    [anon_sym_AMP_AMP] = ACTIONS(143),
    [anon_sym_and] = ACTIONS(143),
    [anon_sym_xor] = ACTIONS(143),
    [anon_sym_CARET_CARET] = ACTIONS(143),
    [anon_sym_or] = ACTIONS(143),
    [anon_sym_PIPE_PIPE] = ACTIONS(143),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(143),
    [anon_sym_ne] = ACTIONS(143),
    [anon_sym_EQ_EQ] = ACTIONS(143),
    [anon_sym_BANG_EQ] = ACTIONS(143),
    [anon_sym_concat] = ACTIONS(143),
    [anon_sym_LPAREN] = ACTIONS(143),
    [anon_sym_RPAREN] = ACTIONS(143),
    [anon_sym_ends_with] = ACTIONS(143),
    [anon_sym_len] = ACTIONS(143),
    [anon_sym_lookup_json_string] = ACTIONS(143),
    [anon_sym_lower] = ACTIONS(143),
    [anon_sym_regex_replace] = ACTIONS(143),
    [anon_sym_remove_bytes] = ACTIONS(143),
    [anon_sym_starts_with] = ACTIONS(143),
    [anon_sym_to_string] = ACTIONS(143),
    [anon_sym_upper] = ACTIONS(143),
    [anon_sym_url_decode] = ACTIONS(143),
    [anon_sym_uuidv4] = ACTIONS(143),
    [anon_sym_not] = ACTIONS(143),
    [anon_sym_BANG] = ACTIONS(145),
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
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(147),
    [anon_sym_AMP_AMP] = ACTIONS(147),
    [anon_sym_and] = ACTIONS(147),
    [anon_sym_xor] = ACTIONS(147),
    [anon_sym_CARET_CARET] = ACTIONS(147),
    [anon_sym_or] = ACTIONS(147),
    [anon_sym_PIPE_PIPE] = ACTIONS(147),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(149),
    [anon_sym_ne] = ACTIONS(149),
    [anon_sym_EQ_EQ] = ACTIONS(149),
    [anon_sym_BANG_EQ] = ACTIONS(149),
    [anon_sym_concat] = ACTIONS(147),
    [anon_sym_LPAREN] = ACTIONS(147),
    [anon_sym_RPAREN] = ACTIONS(147),
    [anon_sym_ends_with] = ACTIONS(147),
    [anon_sym_len] = ACTIONS(147),
    [anon_sym_lookup_json_string] = ACTIONS(147),
    [anon_sym_lower] = ACTIONS(147),
    [anon_sym_regex_replace] = ACTIONS(147),
    [anon_sym_remove_bytes] = ACTIONS(147),
    [anon_sym_starts_with] = ACTIONS(147),
    [anon_sym_to_string] = ACTIONS(147),
    [anon_sym_upper] = ACTIONS(147),
    [anon_sym_url_decode] = ACTIONS(147),
    [anon_sym_uuidv4] = ACTIONS(147),
    [anon_sym_not] = ACTIONS(147),
    [anon_sym_BANG] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(147),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(147),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(147),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(147),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(151),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(147),
    [anon_sym_ip_DOTsrc] = ACTIONS(151),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(147),
    [anon_sym_http_DOTcookie] = ACTIONS(147),
    [anon_sym_http_DOThost] = ACTIONS(147),
    [anon_sym_http_DOTreferer] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(151),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(147),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(147),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(147),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(151),
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
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(153),
    [anon_sym_AMP_AMP] = ACTIONS(153),
    [anon_sym_and] = ACTIONS(153),
    [anon_sym_xor] = ACTIONS(153),
    [anon_sym_CARET_CARET] = ACTIONS(153),
    [anon_sym_or] = ACTIONS(153),
    [anon_sym_PIPE_PIPE] = ACTIONS(153),
    [anon_sym_RBRACE] = ACTIONS(153),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(153),
    [anon_sym_LPAREN] = ACTIONS(153),
    [anon_sym_RPAREN] = ACTIONS(153),
    [anon_sym_ends_with] = ACTIONS(153),
    [anon_sym_len] = ACTIONS(153),
    [anon_sym_lookup_json_string] = ACTIONS(153),
    [anon_sym_lower] = ACTIONS(153),
    [anon_sym_regex_replace] = ACTIONS(153),
    [anon_sym_remove_bytes] = ACTIONS(153),
    [anon_sym_starts_with] = ACTIONS(153),
    [anon_sym_to_string] = ACTIONS(153),
    [anon_sym_upper] = ACTIONS(153),
    [anon_sym_url_decode] = ACTIONS(153),
    [anon_sym_uuidv4] = ACTIONS(153),
    [sym_ipv4] = ACTIONS(153),
    [anon_sym_SLASH] = ACTIONS(155),
    [anon_sym_not] = ACTIONS(153),
    [anon_sym_BANG] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(153),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(153),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(153),
    [anon_sym_ip_DOTsrc] = ACTIONS(157),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(153),
    [anon_sym_http_DOTcookie] = ACTIONS(153),
    [anon_sym_http_DOThost] = ACTIONS(153),
    [anon_sym_http_DOTreferer] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(153),
    [anon_sym_http_DOTuser_agent] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(153),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(153),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(153),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(153),
    [anon_sym_ssl] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(153),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(153),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(153),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(153),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(159),
    [anon_sym_AMP_AMP] = ACTIONS(159),
    [anon_sym_and] = ACTIONS(159),
    [anon_sym_xor] = ACTIONS(159),
    [anon_sym_CARET_CARET] = ACTIONS(159),
    [anon_sym_or] = ACTIONS(159),
    [anon_sym_PIPE_PIPE] = ACTIONS(159),
    [anon_sym_RBRACE] = ACTIONS(159),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(159),
    [anon_sym_LPAREN] = ACTIONS(159),
    [anon_sym_RPAREN] = ACTIONS(159),
    [anon_sym_ends_with] = ACTIONS(159),
    [anon_sym_len] = ACTIONS(159),
    [anon_sym_lookup_json_string] = ACTIONS(159),
    [anon_sym_lower] = ACTIONS(159),
    [anon_sym_regex_replace] = ACTIONS(159),
    [anon_sym_remove_bytes] = ACTIONS(159),
    [anon_sym_starts_with] = ACTIONS(159),
    [anon_sym_to_string] = ACTIONS(159),
    [anon_sym_upper] = ACTIONS(159),
    [anon_sym_url_decode] = ACTIONS(159),
    [anon_sym_uuidv4] = ACTIONS(159),
    [sym_ipv4] = ACTIONS(159),
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
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(163),
    [anon_sym_AMP_AMP] = ACTIONS(165),
    [anon_sym_and] = ACTIONS(165),
    [anon_sym_xor] = ACTIONS(163),
    [anon_sym_CARET_CARET] = ACTIONS(163),
    [anon_sym_or] = ACTIONS(163),
    [anon_sym_PIPE_PIPE] = ACTIONS(163),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(163),
    [anon_sym_LPAREN] = ACTIONS(163),
    [anon_sym_RPAREN] = ACTIONS(163),
    [anon_sym_ends_with] = ACTIONS(163),
    [anon_sym_len] = ACTIONS(163),
    [anon_sym_lookup_json_string] = ACTIONS(163),
    [anon_sym_lower] = ACTIONS(163),
    [anon_sym_regex_replace] = ACTIONS(163),
    [anon_sym_remove_bytes] = ACTIONS(163),
    [anon_sym_starts_with] = ACTIONS(163),
    [anon_sym_to_string] = ACTIONS(163),
    [anon_sym_upper] = ACTIONS(163),
    [anon_sym_url_decode] = ACTIONS(163),
    [anon_sym_uuidv4] = ACTIONS(163),
    [anon_sym_not] = ACTIONS(163),
    [anon_sym_BANG] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(163),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(163),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(163),
    [anon_sym_ip_DOTsrc] = ACTIONS(167),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(163),
    [anon_sym_http_DOTcookie] = ACTIONS(163),
    [anon_sym_http_DOThost] = ACTIONS(163),
    [anon_sym_http_DOTreferer] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(167),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(163),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(163),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(167),
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
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(163),
    [anon_sym_AMP_AMP] = ACTIONS(165),
    [anon_sym_and] = ACTIONS(165),
    [anon_sym_xor] = ACTIONS(173),
    [anon_sym_CARET_CARET] = ACTIONS(173),
    [anon_sym_or] = ACTIONS(163),
    [anon_sym_PIPE_PIPE] = ACTIONS(163),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(163),
    [anon_sym_LPAREN] = ACTIONS(163),
    [anon_sym_RPAREN] = ACTIONS(163),
    [anon_sym_ends_with] = ACTIONS(163),
    [anon_sym_len] = ACTIONS(163),
    [anon_sym_lookup_json_string] = ACTIONS(163),
    [anon_sym_lower] = ACTIONS(163),
    [anon_sym_regex_replace] = ACTIONS(163),
    [anon_sym_remove_bytes] = ACTIONS(163),
    [anon_sym_starts_with] = ACTIONS(163),
    [anon_sym_to_string] = ACTIONS(163),
    [anon_sym_upper] = ACTIONS(163),
    [anon_sym_url_decode] = ACTIONS(163),
    [anon_sym_uuidv4] = ACTIONS(163),
    [anon_sym_not] = ACTIONS(163),
    [anon_sym_BANG] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(163),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(163),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(163),
    [anon_sym_ip_DOTsrc] = ACTIONS(167),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(163),
    [anon_sym_http_DOTcookie] = ACTIONS(163),
    [anon_sym_http_DOThost] = ACTIONS(163),
    [anon_sym_http_DOTreferer] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(167),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(163),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(163),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(167),
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
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [20] = {
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
    [anon_sym_ends_with] = ACTIONS(175),
    [anon_sym_len] = ACTIONS(175),
    [anon_sym_lookup_json_string] = ACTIONS(175),
    [anon_sym_lower] = ACTIONS(175),
    [anon_sym_regex_replace] = ACTIONS(175),
    [anon_sym_remove_bytes] = ACTIONS(175),
    [anon_sym_starts_with] = ACTIONS(175),
    [anon_sym_to_string] = ACTIONS(175),
    [anon_sym_upper] = ACTIONS(175),
    [anon_sym_url_decode] = ACTIONS(175),
    [anon_sym_uuidv4] = ACTIONS(175),
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
  [21] = {
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
    [anon_sym_ends_with] = ACTIONS(179),
    [anon_sym_len] = ACTIONS(179),
    [anon_sym_lookup_json_string] = ACTIONS(179),
    [anon_sym_lower] = ACTIONS(179),
    [anon_sym_regex_replace] = ACTIONS(179),
    [anon_sym_remove_bytes] = ACTIONS(179),
    [anon_sym_starts_with] = ACTIONS(179),
    [anon_sym_to_string] = ACTIONS(179),
    [anon_sym_upper] = ACTIONS(179),
    [anon_sym_url_decode] = ACTIONS(179),
    [anon_sym_uuidv4] = ACTIONS(179),
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
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [23] = {
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
    [anon_sym_ends_with] = ACTIONS(183),
    [anon_sym_len] = ACTIONS(183),
    [anon_sym_lookup_json_string] = ACTIONS(183),
    [anon_sym_lower] = ACTIONS(183),
    [anon_sym_regex_replace] = ACTIONS(183),
    [anon_sym_remove_bytes] = ACTIONS(183),
    [anon_sym_starts_with] = ACTIONS(183),
    [anon_sym_to_string] = ACTIONS(183),
    [anon_sym_upper] = ACTIONS(183),
    [anon_sym_url_decode] = ACTIONS(183),
    [anon_sym_uuidv4] = ACTIONS(183),
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
  [24] = {
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
    [anon_sym_ends_with] = ACTIONS(163),
    [anon_sym_len] = ACTIONS(163),
    [anon_sym_lookup_json_string] = ACTIONS(163),
    [anon_sym_lower] = ACTIONS(163),
    [anon_sym_regex_replace] = ACTIONS(163),
    [anon_sym_remove_bytes] = ACTIONS(163),
    [anon_sym_starts_with] = ACTIONS(163),
    [anon_sym_to_string] = ACTIONS(163),
    [anon_sym_upper] = ACTIONS(163),
    [anon_sym_url_decode] = ACTIONS(163),
    [anon_sym_uuidv4] = ACTIONS(163),
    [anon_sym_not] = ACTIONS(163),
    [anon_sym_BANG] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(163),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(163),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(163),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(163),
    [anon_sym_ip_DOTsrc] = ACTIONS(167),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(163),
    [anon_sym_http_DOTcookie] = ACTIONS(163),
    [anon_sym_http_DOThost] = ACTIONS(163),
    [anon_sym_http_DOTreferer] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(167),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(163),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(163),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(163),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(167),
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
  [25] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [26] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [28] = {
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
    [anon_sym_ends_with] = ACTIONS(187),
    [anon_sym_len] = ACTIONS(187),
    [anon_sym_lookup_json_string] = ACTIONS(187),
    [anon_sym_lower] = ACTIONS(187),
    [anon_sym_regex_replace] = ACTIONS(187),
    [anon_sym_remove_bytes] = ACTIONS(187),
    [anon_sym_starts_with] = ACTIONS(187),
    [anon_sym_to_string] = ACTIONS(187),
    [anon_sym_upper] = ACTIONS(187),
    [anon_sym_url_decode] = ACTIONS(187),
    [anon_sym_uuidv4] = ACTIONS(187),
    [anon_sym_not] = ACTIONS(187),
    [anon_sym_BANG] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(187),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(187),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(189),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(187),
    [anon_sym_ip_DOTsrc] = ACTIONS(189),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(187),
    [anon_sym_http_DOThost] = ACTIONS(187),
    [anon_sym_http_DOTreferer] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(189),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(187),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(187),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(187),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(189),
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
  [29] = {
    [ts_builtin_sym_end] = ACTIONS(191),
    [anon_sym_AMP_AMP] = ACTIONS(191),
    [anon_sym_and] = ACTIONS(191),
    [anon_sym_xor] = ACTIONS(191),
    [anon_sym_CARET_CARET] = ACTIONS(191),
    [anon_sym_or] = ACTIONS(191),
    [anon_sym_PIPE_PIPE] = ACTIONS(191),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(191),
    [anon_sym_LPAREN] = ACTIONS(191),
    [anon_sym_RPAREN] = ACTIONS(191),
    [anon_sym_ends_with] = ACTIONS(191),
    [anon_sym_len] = ACTIONS(191),
    [anon_sym_lookup_json_string] = ACTIONS(191),
    [anon_sym_lower] = ACTIONS(191),
    [anon_sym_regex_replace] = ACTIONS(191),
    [anon_sym_remove_bytes] = ACTIONS(191),
    [anon_sym_starts_with] = ACTIONS(191),
    [anon_sym_to_string] = ACTIONS(191),
    [anon_sym_upper] = ACTIONS(191),
    [anon_sym_url_decode] = ACTIONS(191),
    [anon_sym_uuidv4] = ACTIONS(191),
    [anon_sym_not] = ACTIONS(191),
    [anon_sym_BANG] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(191),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(191),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(193),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(191),
    [anon_sym_ip_DOTsrc] = ACTIONS(193),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(191),
    [anon_sym_http_DOTcookie] = ACTIONS(191),
    [anon_sym_http_DOThost] = ACTIONS(191),
    [anon_sym_http_DOTreferer] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(191),
    [anon_sym_http_DOTuser_agent] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(191),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(191),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(191),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(191),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(191),
    [anon_sym_ssl] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(191),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(191),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(191),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(191),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(191),
  },
  [30] = {
    [ts_builtin_sym_end] = ACTIONS(195),
    [anon_sym_AMP_AMP] = ACTIONS(195),
    [anon_sym_and] = ACTIONS(195),
    [anon_sym_xor] = ACTIONS(195),
    [anon_sym_CARET_CARET] = ACTIONS(195),
    [anon_sym_or] = ACTIONS(195),
    [anon_sym_PIPE_PIPE] = ACTIONS(195),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(195),
    [anon_sym_LPAREN] = ACTIONS(195),
    [anon_sym_RPAREN] = ACTIONS(195),
    [anon_sym_ends_with] = ACTIONS(195),
    [anon_sym_len] = ACTIONS(195),
    [anon_sym_lookup_json_string] = ACTIONS(195),
    [anon_sym_lower] = ACTIONS(195),
    [anon_sym_regex_replace] = ACTIONS(195),
    [anon_sym_remove_bytes] = ACTIONS(195),
    [anon_sym_starts_with] = ACTIONS(195),
    [anon_sym_to_string] = ACTIONS(195),
    [anon_sym_upper] = ACTIONS(195),
    [anon_sym_url_decode] = ACTIONS(195),
    [anon_sym_uuidv4] = ACTIONS(195),
    [anon_sym_not] = ACTIONS(195),
    [anon_sym_BANG] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(195),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(195),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(195),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(195),
    [anon_sym_ip_DOTsrc] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(195),
    [anon_sym_http_DOTcookie] = ACTIONS(195),
    [anon_sym_http_DOThost] = ACTIONS(195),
    [anon_sym_http_DOTreferer] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(195),
    [anon_sym_http_DOTuser_agent] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(195),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(195),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(195),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(195),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(195),
    [anon_sym_ssl] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(195),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(195),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(195),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(195),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(195),
  },
  [31] = {
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
    [anon_sym_ends_with] = ACTIONS(199),
    [anon_sym_len] = ACTIONS(199),
    [anon_sym_lookup_json_string] = ACTIONS(199),
    [anon_sym_lower] = ACTIONS(199),
    [anon_sym_regex_replace] = ACTIONS(199),
    [anon_sym_remove_bytes] = ACTIONS(199),
    [anon_sym_starts_with] = ACTIONS(199),
    [anon_sym_to_string] = ACTIONS(199),
    [anon_sym_upper] = ACTIONS(199),
    [anon_sym_url_decode] = ACTIONS(199),
    [anon_sym_uuidv4] = ACTIONS(199),
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
  [32] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [33] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [34] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [35] = {
    [ts_builtin_sym_end] = ACTIONS(203),
    [anon_sym_AMP_AMP] = ACTIONS(203),
    [anon_sym_and] = ACTIONS(203),
    [anon_sym_xor] = ACTIONS(203),
    [anon_sym_CARET_CARET] = ACTIONS(203),
    [anon_sym_or] = ACTIONS(203),
    [anon_sym_PIPE_PIPE] = ACTIONS(203),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(203),
    [anon_sym_LPAREN] = ACTIONS(203),
    [anon_sym_RPAREN] = ACTIONS(203),
    [anon_sym_ends_with] = ACTIONS(203),
    [anon_sym_len] = ACTIONS(203),
    [anon_sym_lookup_json_string] = ACTIONS(203),
    [anon_sym_lower] = ACTIONS(203),
    [anon_sym_regex_replace] = ACTIONS(203),
    [anon_sym_remove_bytes] = ACTIONS(203),
    [anon_sym_starts_with] = ACTIONS(203),
    [anon_sym_to_string] = ACTIONS(203),
    [anon_sym_upper] = ACTIONS(203),
    [anon_sym_url_decode] = ACTIONS(203),
    [anon_sym_uuidv4] = ACTIONS(203),
    [anon_sym_not] = ACTIONS(203),
    [anon_sym_BANG] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(203),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(203),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(203),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(203),
    [anon_sym_ip_DOTsrc] = ACTIONS(205),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(203),
    [anon_sym_http_DOTcookie] = ACTIONS(203),
    [anon_sym_http_DOThost] = ACTIONS(203),
    [anon_sym_http_DOTreferer] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(205),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(203),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(203),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(203),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(205),
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
  [36] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [37] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [38] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [39] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [40] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [41] = {
    [ts_builtin_sym_end] = ACTIONS(169),
    [anon_sym_AMP_AMP] = ACTIONS(169),
    [anon_sym_and] = ACTIONS(169),
    [anon_sym_xor] = ACTIONS(169),
    [anon_sym_CARET_CARET] = ACTIONS(169),
    [anon_sym_or] = ACTIONS(169),
    [anon_sym_PIPE_PIPE] = ACTIONS(169),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(169),
    [anon_sym_LPAREN] = ACTIONS(169),
    [anon_sym_RPAREN] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_not] = ACTIONS(169),
    [anon_sym_BANG] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(169),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(169),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(171),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(169),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
  },
  [42] = {
    [ts_builtin_sym_end] = ACTIONS(207),
    [anon_sym_AMP_AMP] = ACTIONS(207),
    [anon_sym_and] = ACTIONS(207),
    [anon_sym_xor] = ACTIONS(207),
    [anon_sym_CARET_CARET] = ACTIONS(207),
    [anon_sym_or] = ACTIONS(207),
    [anon_sym_PIPE_PIPE] = ACTIONS(207),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(207),
    [anon_sym_LPAREN] = ACTIONS(207),
    [anon_sym_RPAREN] = ACTIONS(207),
    [anon_sym_ends_with] = ACTIONS(207),
    [anon_sym_len] = ACTIONS(207),
    [anon_sym_lookup_json_string] = ACTIONS(207),
    [anon_sym_lower] = ACTIONS(207),
    [anon_sym_regex_replace] = ACTIONS(207),
    [anon_sym_remove_bytes] = ACTIONS(207),
    [anon_sym_starts_with] = ACTIONS(207),
    [anon_sym_to_string] = ACTIONS(207),
    [anon_sym_upper] = ACTIONS(207),
    [anon_sym_url_decode] = ACTIONS(207),
    [anon_sym_uuidv4] = ACTIONS(207),
    [anon_sym_not] = ACTIONS(207),
    [anon_sym_BANG] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(207),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(207),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(207),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(207),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(207),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(207),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(207),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(207),
    [anon_sym_ip_DOTsrc] = ACTIONS(209),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(207),
    [anon_sym_http_DOTcookie] = ACTIONS(207),
    [anon_sym_http_DOThost] = ACTIONS(207),
    [anon_sym_http_DOTreferer] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(207),
    [anon_sym_http_DOTuser_agent] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(207),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(207),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(207),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(207),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(207),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(207),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(207),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(207),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(207),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(207),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(207),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(207),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(207),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(207),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(207),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(207),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(207),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(207),
    [anon_sym_ssl] = ACTIONS(207),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(207),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(207),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(207),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(207),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(207),
  },
  [43] = {
    [ts_builtin_sym_end] = ACTIONS(211),
    [anon_sym_AMP_AMP] = ACTIONS(165),
    [anon_sym_and] = ACTIONS(165),
    [anon_sym_xor] = ACTIONS(173),
    [anon_sym_CARET_CARET] = ACTIONS(173),
    [anon_sym_or] = ACTIONS(213),
    [anon_sym_PIPE_PIPE] = ACTIONS(213),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(211),
    [anon_sym_LPAREN] = ACTIONS(211),
    [anon_sym_ends_with] = ACTIONS(211),
    [anon_sym_len] = ACTIONS(211),
    [anon_sym_lookup_json_string] = ACTIONS(211),
    [anon_sym_lower] = ACTIONS(211),
    [anon_sym_regex_replace] = ACTIONS(211),
    [anon_sym_remove_bytes] = ACTIONS(211),
    [anon_sym_starts_with] = ACTIONS(211),
    [anon_sym_to_string] = ACTIONS(211),
    [anon_sym_upper] = ACTIONS(211),
    [anon_sym_url_decode] = ACTIONS(211),
    [anon_sym_uuidv4] = ACTIONS(211),
    [anon_sym_not] = ACTIONS(211),
    [anon_sym_BANG] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(211),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(211),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(211),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(211),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(211),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(211),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(211),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(211),
    [anon_sym_ip_DOTsrc] = ACTIONS(215),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(211),
    [anon_sym_http_DOTcookie] = ACTIONS(211),
    [anon_sym_http_DOThost] = ACTIONS(211),
    [anon_sym_http_DOTreferer] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(215),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(211),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(211),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(211),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(211),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(211),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(215),
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
  [44] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(217),
    [anon_sym_LPAREN] = ACTIONS(217),
    [anon_sym_ends_with] = ACTIONS(217),
    [anon_sym_len] = ACTIONS(217),
    [anon_sym_lookup_json_string] = ACTIONS(217),
    [anon_sym_lower] = ACTIONS(217),
    [anon_sym_regex_replace] = ACTIONS(217),
    [anon_sym_remove_bytes] = ACTIONS(217),
    [anon_sym_starts_with] = ACTIONS(217),
    [anon_sym_to_string] = ACTIONS(217),
    [anon_sym_upper] = ACTIONS(217),
    [anon_sym_url_decode] = ACTIONS(217),
    [anon_sym_uuidv4] = ACTIONS(217),
    [anon_sym_not] = ACTIONS(217),
    [anon_sym_BANG] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(217),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(217),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(219),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(217),
    [anon_sym_ip_DOTsrc] = ACTIONS(219),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(217),
    [anon_sym_http_DOTcookie] = ACTIONS(217),
    [anon_sym_http_DOThost] = ACTIONS(217),
    [anon_sym_http_DOTreferer] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(217),
    [anon_sym_http_DOTuser_agent] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(217),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(217),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(217),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(217),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(217),
    [anon_sym_ssl] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(217),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(217),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(217),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(217),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(217),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(223), 4,
      anon_sym_LT,
      anon_sym_GT,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(221), 43,
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
  [55] = 7,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(225), 1,
      anon_sym_RPAREN,
    ACTIONS(227), 1,
      sym_string,
    STATE(47), 1,
      aux_sym_concat_func_repeat1,
    STATE(49), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [102] = 7,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(229), 1,
      anon_sym_RPAREN,
    ACTIONS(231), 1,
      sym_string,
    STATE(47), 1,
      aux_sym_concat_func_repeat1,
    STATE(49), 1,
      sym_string_field,
    ACTIONS(237), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(234), 25,
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
  [149] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(240), 1,
      anon_sym_cf_DOTrandom_seed,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(134), 2,
      sym_string_field,
      sym_bytes_field,
    ACTIONS(43), 25,
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
  [191] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(242), 1,
      anon_sym_COMMA,
    ACTIONS(246), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(244), 27,
      anon_sym_RPAREN,
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
  [231] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(227), 1,
      sym_string,
    STATE(46), 1,
      aux_sym_concat_func_repeat1,
    STATE(49), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [275] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(240), 1,
      anon_sym_cf_DOTrandom_seed,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(131), 2,
      sym_string_field,
      sym_bytes_field,
    ACTIONS(43), 25,
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
  [317] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(248), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(229), 27,
      anon_sym_RPAREN,
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
  [354] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(250), 1,
      sym_string,
    STATE(126), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [395] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(252), 1,
      sym_string,
    STATE(137), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [436] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(132), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [474] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(123), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [512] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(129), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [550] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(143), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [588] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(148), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [626] = 4,
    ACTIONS(3), 1,
      sym_comment,
    STATE(97), 1,
      sym_string_field,
    ACTIONS(45), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(43), 25,
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
  [664] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(37), 1,
      anon_sym_cf_DOTwaf_DOTscore,
    ACTIONS(41), 2,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
    STATE(150), 3,
      sym_number_field,
      sym_ip_field,
      sym_bool_field,
    ACTIONS(53), 8,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
      anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
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
  [701] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(256), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(254), 14,
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
  [725] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(260), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(258), 14,
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
  [749] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(264), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(262), 14,
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
  [773] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(268), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(266), 14,
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
  [797] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(272), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(270), 14,
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
  [821] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(276), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(274), 14,
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
  [845] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(280), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(278), 14,
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
  [869] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(284), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(282), 14,
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
  [893] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(288), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(286), 14,
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
  [917] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(292), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(290), 14,
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
  [941] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(296), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(294), 14,
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
  [965] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(300), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(298), 14,
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
  [989] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(302), 1,
      anon_sym_in,
    ACTIONS(304), 1,
      anon_sym_eq,
    ACTIONS(306), 1,
      anon_sym_ne,
    ACTIONS(308), 1,
      anon_sym_lt,
    ACTIONS(310), 1,
      anon_sym_le,
    ACTIONS(312), 1,
      anon_sym_gt,
    ACTIONS(314), 1,
      anon_sym_ge,
    ACTIONS(316), 1,
      anon_sym_EQ_EQ,
    ACTIONS(318), 1,
      anon_sym_BANG_EQ,
    ACTIONS(320), 1,
      anon_sym_LT,
    ACTIONS(322), 1,
      anon_sym_LT_EQ,
    ACTIONS(324), 1,
      anon_sym_GT,
    ACTIONS(326), 1,
      anon_sym_GT_EQ,
    ACTIONS(328), 1,
      anon_sym_contains,
    ACTIONS(330), 1,
      anon_sym_matches,
    ACTIONS(332), 1,
      anon_sym_TILDE,
  [1041] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(336), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(334), 14,
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
  [1065] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(340), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(338), 12,
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
  [1087] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(342), 1,
      anon_sym_in,
    ACTIONS(346), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(344), 10,
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
  [1110] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(350), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(348), 11,
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
  [1131] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(354), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(352), 11,
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
  [1152] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(356), 1,
      anon_sym_RPAREN,
    ACTIONS(165), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(173), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(213), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [1171] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(358), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [1183] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(360), 1,
      anon_sym_RBRACE,
    ACTIONS(362), 1,
      sym_ipv4,
    STATE(82), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1198] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(365), 1,
      anon_sym_in,
    ACTIONS(367), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [1211] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(369), 1,
      anon_sym_RBRACE,
    ACTIONS(371), 1,
      sym_ipv4,
    STATE(82), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1226] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(373), 1,
      anon_sym_COMMA,
    ACTIONS(375), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1238] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(377), 1,
      anon_sym_RPAREN,
    STATE(86), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(379), 2,
      sym_number,
      sym_string,
  [1252] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(382), 1,
      anon_sym_RPAREN,
    STATE(86), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(384), 2,
      sym_number,
      sym_string,
  [1266] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(371), 1,
      sym_ipv4,
    STATE(84), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1278] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(386), 1,
      anon_sym_LBRACE,
    ACTIONS(388), 1,
      sym_ip_list,
    STATE(42), 1,
      sym_ip_set,
  [1291] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(371), 1,
      sym_ipv4,
    STATE(23), 2,
      sym__ip,
      sym_ip_range,
  [1302] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(390), 1,
      anon_sym_RBRACE,
    ACTIONS(392), 1,
      sym_string,
    STATE(91), 1,
      aux_sym_string_set_repeat1,
  [1315] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(395), 1,
      anon_sym_RBRACE,
    ACTIONS(397), 1,
      sym_number,
    STATE(92), 1,
      aux_sym_number_set_repeat1,
  [1328] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(377), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1337] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(23), 1,
      sym_boolean,
    ACTIONS(400), 2,
      anon_sym_true,
      anon_sym_false,
  [1348] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(402), 1,
      anon_sym_RBRACE,
    ACTIONS(404), 1,
      sym_string,
    STATE(91), 1,
      aux_sym_string_set_repeat1,
  [1361] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(406), 1,
      anon_sym_RBRACE,
    ACTIONS(408), 1,
      sym_number,
    STATE(92), 1,
      aux_sym_number_set_repeat1,
  [1374] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(87), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(384), 2,
      sym_number,
      sym_string,
  [1385] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(410), 1,
      sym_number,
    STATE(96), 1,
      aux_sym_number_set_repeat1,
  [1395] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(412), 1,
      sym_string,
    STATE(95), 1,
      aux_sym_string_set_repeat1,
  [1405] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(414), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [1413] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(240), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(141), 1,
      sym_bytes_field,
  [1423] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(416), 1,
      anon_sym_LBRACE,
    STATE(42), 1,
      sym_number_set,
  [1433] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(418), 1,
      anon_sym_LBRACE,
    STATE(35), 1,
      sym_string_set,
  [1443] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(420), 1,
      sym_string,
  [1450] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(422), 1,
      aux_sym_ip_range_token1,
  [1457] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(424), 1,
      sym_string,
  [1464] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(426), 1,
      sym_string,
  [1471] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(428), 1,
      sym_string,
  [1478] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(430), 1,
      sym_string,
  [1485] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(432), 1,
      sym_string,
  [1492] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(434), 1,
      sym_string,
  [1499] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(436), 1,
      sym_string,
  [1506] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(438), 1,
      sym_string,
  [1513] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(440), 1,
      sym_string,
  [1520] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(442), 1,
      sym_string,
  [1527] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(444), 1,
      sym_string,
  [1534] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(446), 1,
      anon_sym_RBRACK,
  [1541] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(448), 1,
      anon_sym_RBRACK,
  [1548] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(450), 1,
      sym_string,
  [1555] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(452), 1,
      sym_string,
  [1562] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(454), 1,
      sym_string,
  [1569] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(456), 1,
      sym_string,
  [1576] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(458), 1,
      anon_sym_COMMA,
  [1583] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(460), 1,
      sym_string,
  [1590] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      sym_string,
  [1597] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(464), 1,
      anon_sym_COMMA,
  [1604] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(466), 1,
      sym_string,
  [1611] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(468), 1,
      sym_string,
  [1618] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(470), 1,
      anon_sym_COMMA,
  [1625] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(472), 1,
      sym_number,
  [1632] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(474), 1,
      anon_sym_RPAREN,
  [1639] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(476), 1,
      anon_sym_RPAREN,
  [1646] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(478), 1,
      anon_sym_LPAREN,
  [1653] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      anon_sym_COMMA,
  [1660] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(482), 1,
      sym_number,
  [1667] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(484), 1,
      anon_sym_LBRACK,
  [1674] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(486), 1,
      anon_sym_COMMA,
  [1681] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      anon_sym_LBRACK,
  [1688] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(490), 1,
      anon_sym_LBRACK,
  [1695] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(492), 1,
      anon_sym_RPAREN,
  [1702] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      anon_sym_RPAREN,
  [1709] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(496), 1,
      ts_builtin_sym_end,
  [1716] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(498), 1,
      anon_sym_RPAREN,
  [1723] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(500), 1,
      anon_sym_COMMA,
  [1730] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(502), 1,
      anon_sym_RPAREN,
  [1737] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(504), 1,
      anon_sym_RPAREN,
  [1744] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(506), 1,
      anon_sym_LBRACK,
  [1751] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(508), 1,
      anon_sym_RPAREN,
  [1758] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK,
  [1765] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(512), 1,
      anon_sym_RPAREN,
  [1772] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_LPAREN,
  [1779] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(516), 1,
      anon_sym_LPAREN,
  [1786] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(518), 1,
      anon_sym_LPAREN,
  [1793] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 1,
      sym_number,
  [1800] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(522), 1,
      anon_sym_LPAREN,
  [1807] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LPAREN,
  [1814] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(526), 1,
      anon_sym_LPAREN,
  [1821] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      anon_sym_LPAREN,
  [1828] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(530), 1,
      sym_string,
  [1835] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(532), 1,
      anon_sym_LPAREN,
  [1842] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(534), 1,
      anon_sym_LPAREN,
  [1849] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(536), 1,
      anon_sym_RBRACK,
  [1856] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      anon_sym_RPAREN,
  [1863] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(540), 1,
      anon_sym_LPAREN,
  [1870] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      anon_sym_LPAREN,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(45)] = 0,
  [SMALL_STATE(46)] = 55,
  [SMALL_STATE(47)] = 102,
  [SMALL_STATE(48)] = 149,
  [SMALL_STATE(49)] = 191,
  [SMALL_STATE(50)] = 231,
  [SMALL_STATE(51)] = 275,
  [SMALL_STATE(52)] = 317,
  [SMALL_STATE(53)] = 354,
  [SMALL_STATE(54)] = 395,
  [SMALL_STATE(55)] = 436,
  [SMALL_STATE(56)] = 474,
  [SMALL_STATE(57)] = 512,
  [SMALL_STATE(58)] = 550,
  [SMALL_STATE(59)] = 588,
  [SMALL_STATE(60)] = 626,
  [SMALL_STATE(61)] = 664,
  [SMALL_STATE(62)] = 701,
  [SMALL_STATE(63)] = 725,
  [SMALL_STATE(64)] = 749,
  [SMALL_STATE(65)] = 773,
  [SMALL_STATE(66)] = 797,
  [SMALL_STATE(67)] = 821,
  [SMALL_STATE(68)] = 845,
  [SMALL_STATE(69)] = 869,
  [SMALL_STATE(70)] = 893,
  [SMALL_STATE(71)] = 917,
  [SMALL_STATE(72)] = 941,
  [SMALL_STATE(73)] = 965,
  [SMALL_STATE(74)] = 989,
  [SMALL_STATE(75)] = 1041,
  [SMALL_STATE(76)] = 1065,
  [SMALL_STATE(77)] = 1087,
  [SMALL_STATE(78)] = 1110,
  [SMALL_STATE(79)] = 1131,
  [SMALL_STATE(80)] = 1152,
  [SMALL_STATE(81)] = 1171,
  [SMALL_STATE(82)] = 1183,
  [SMALL_STATE(83)] = 1198,
  [SMALL_STATE(84)] = 1211,
  [SMALL_STATE(85)] = 1226,
  [SMALL_STATE(86)] = 1238,
  [SMALL_STATE(87)] = 1252,
  [SMALL_STATE(88)] = 1266,
  [SMALL_STATE(89)] = 1278,
  [SMALL_STATE(90)] = 1291,
  [SMALL_STATE(91)] = 1302,
  [SMALL_STATE(92)] = 1315,
  [SMALL_STATE(93)] = 1328,
  [SMALL_STATE(94)] = 1337,
  [SMALL_STATE(95)] = 1348,
  [SMALL_STATE(96)] = 1361,
  [SMALL_STATE(97)] = 1374,
  [SMALL_STATE(98)] = 1385,
  [SMALL_STATE(99)] = 1395,
  [SMALL_STATE(100)] = 1405,
  [SMALL_STATE(101)] = 1413,
  [SMALL_STATE(102)] = 1423,
  [SMALL_STATE(103)] = 1433,
  [SMALL_STATE(104)] = 1443,
  [SMALL_STATE(105)] = 1450,
  [SMALL_STATE(106)] = 1457,
  [SMALL_STATE(107)] = 1464,
  [SMALL_STATE(108)] = 1471,
  [SMALL_STATE(109)] = 1478,
  [SMALL_STATE(110)] = 1485,
  [SMALL_STATE(111)] = 1492,
  [SMALL_STATE(112)] = 1499,
  [SMALL_STATE(113)] = 1506,
  [SMALL_STATE(114)] = 1513,
  [SMALL_STATE(115)] = 1520,
  [SMALL_STATE(116)] = 1527,
  [SMALL_STATE(117)] = 1534,
  [SMALL_STATE(118)] = 1541,
  [SMALL_STATE(119)] = 1548,
  [SMALL_STATE(120)] = 1555,
  [SMALL_STATE(121)] = 1562,
  [SMALL_STATE(122)] = 1569,
  [SMALL_STATE(123)] = 1576,
  [SMALL_STATE(124)] = 1583,
  [SMALL_STATE(125)] = 1590,
  [SMALL_STATE(126)] = 1597,
  [SMALL_STATE(127)] = 1604,
  [SMALL_STATE(128)] = 1611,
  [SMALL_STATE(129)] = 1618,
  [SMALL_STATE(130)] = 1625,
  [SMALL_STATE(131)] = 1632,
  [SMALL_STATE(132)] = 1639,
  [SMALL_STATE(133)] = 1646,
  [SMALL_STATE(134)] = 1653,
  [SMALL_STATE(135)] = 1660,
  [SMALL_STATE(136)] = 1667,
  [SMALL_STATE(137)] = 1674,
  [SMALL_STATE(138)] = 1681,
  [SMALL_STATE(139)] = 1688,
  [SMALL_STATE(140)] = 1695,
  [SMALL_STATE(141)] = 1702,
  [SMALL_STATE(142)] = 1709,
  [SMALL_STATE(143)] = 1716,
  [SMALL_STATE(144)] = 1723,
  [SMALL_STATE(145)] = 1730,
  [SMALL_STATE(146)] = 1737,
  [SMALL_STATE(147)] = 1744,
  [SMALL_STATE(148)] = 1751,
  [SMALL_STATE(149)] = 1758,
  [SMALL_STATE(150)] = 1765,
  [SMALL_STATE(151)] = 1772,
  [SMALL_STATE(152)] = 1779,
  [SMALL_STATE(153)] = 1786,
  [SMALL_STATE(154)] = 1793,
  [SMALL_STATE(155)] = 1800,
  [SMALL_STATE(156)] = 1807,
  [SMALL_STATE(157)] = 1814,
  [SMALL_STATE(158)] = 1821,
  [SMALL_STATE(159)] = 1828,
  [SMALL_STATE(160)] = 1835,
  [SMALL_STATE(161)] = 1842,
  [SMALL_STATE(162)] = 1849,
  [SMALL_STATE(163)] = 1856,
  [SMALL_STATE(164)] = 1863,
  [SMALL_STATE(165)] = 1870,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(133),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(165),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(164),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(161),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(160),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(158),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(157),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(156),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(155),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(153),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(152),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(151),
  [33] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [35] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [37] = {.entry = {.count = 1, .reusable = false}}, SHIFT(76),
  [39] = {.entry = {.count = 1, .reusable = false}}, SHIFT(81),
  [41] = {.entry = {.count = 1, .reusable = true}}, SHIFT(81),
  [43] = {.entry = {.count = 1, .reusable = true}}, SHIFT(45),
  [45] = {.entry = {.count = 1, .reusable = false}}, SHIFT(45),
  [47] = {.entry = {.count = 1, .reusable = true}}, SHIFT(149),
  [49] = {.entry = {.count = 1, .reusable = false}}, SHIFT(149),
  [51] = {.entry = {.count = 1, .reusable = true}}, SHIFT(147),
  [53] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [55] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [57] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [59] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(133),
  [62] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(5),
  [65] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(165),
  [68] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(164),
  [71] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(161),
  [74] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(160),
  [77] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(158),
  [80] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(157),
  [83] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(156),
  [86] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(155),
  [89] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(153),
  [92] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(152),
  [95] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(151),
  [98] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(44),
  [101] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(76),
  [104] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(76),
  [107] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(81),
  [110] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(81),
  [113] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(45),
  [116] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(45),
  [119] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(149),
  [122] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(149),
  [125] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(147),
  [128] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(9),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_field, 1),
  [133] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_field, 1),
  [135] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_starts_with_func, 6, .production_id = 10),
  [137] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_starts_with_func, 6, .production_id = 10),
  [139] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ends_with_func, 6, .production_id = 10),
  [141] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ends_with_func, 6, .production_id = 10),
  [143] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 1),
  [145] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 1),
  [147] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__expression, 1),
  [149] = {.entry = {.count = 1, .reusable = true}}, SHIFT(94),
  [151] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__expression, 1),
  [153] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [155] = {.entry = {.count = 1, .reusable = true}}, SHIFT(105),
  [157] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [159] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 9),
  [161] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 9),
  [163] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 3),
  [165] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [167] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 3),
  [169] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 4),
  [171] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 4),
  [173] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [175] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [177] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [179] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [181] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [183] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 3),
  [185] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 3),
  [187] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [189] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [191] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [193] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [195] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3, .production_id = 2),
  [197] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3, .production_id = 2),
  [199] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [201] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [203] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 4),
  [205] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 4),
  [207] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 3),
  [209] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 3),
  [211] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [213] = {.entry = {.count = 1, .reusable = true}}, SHIFT(4),
  [215] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [217] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [219] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [221] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [223] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [225] = {.entry = {.count = 1, .reusable = true}}, SHIFT(72),
  [227] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [229] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 2),
  [231] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 2), SHIFT_REPEAT(49),
  [234] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 2), SHIFT_REPEAT(45),
  [237] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_concat_func_repeat1, 2), SHIFT_REPEAT(45),
  [240] = {.entry = {.count = 1, .reusable = true}}, SHIFT(100),
  [242] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [244] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_concat_func_repeat1, 1),
  [246] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_concat_func_repeat1, 1),
  [248] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_concat_func_repeat1, 2),
  [250] = {.entry = {.count = 1, .reusable = true}}, SHIFT(126),
  [252] = {.entry = {.count = 1, .reusable = true}}, SHIFT(137),
  [254] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_lower_func, 4, .production_id = 5),
  [256] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_lower_func, 4, .production_id = 5),
  [258] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 1),
  [260] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 1),
  [262] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_regex_replace_func, 8, .production_id = 13),
  [264] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_regex_replace_func, 8, .production_id = 13),
  [266] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__stringlike_field, 7, .production_id = 12),
  [268] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__stringlike_field, 7, .production_id = 12),
  [270] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 11),
  [272] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 11),
  [274] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_to_string_func, 4, .production_id = 5),
  [276] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_to_string_func, 4, .production_id = 5),
  [278] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__stringlike_field, 4, .production_id = 7),
  [280] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__stringlike_field, 4, .production_id = 7),
  [282] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_upper_func, 4, .production_id = 5),
  [284] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_upper_func, 4, .production_id = 5),
  [286] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_uuid_func, 4, .production_id = 6),
  [288] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_uuid_func, 4, .production_id = 6),
  [290] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [292] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [294] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_concat_func, 6),
  [296] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_concat_func, 6),
  [298] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_url_decode_func, 4, .production_id = 5),
  [300] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_url_decode_func, 4, .production_id = 5),
  [302] = {.entry = {.count = 1, .reusable = true}}, SHIFT(103),
  [304] = {.entry = {.count = 1, .reusable = true}}, SHIFT(128),
  [306] = {.entry = {.count = 1, .reusable = true}}, SHIFT(124),
  [308] = {.entry = {.count = 1, .reusable = true}}, SHIFT(122),
  [310] = {.entry = {.count = 1, .reusable = true}}, SHIFT(121),
  [312] = {.entry = {.count = 1, .reusable = true}}, SHIFT(119),
  [314] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [316] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [318] = {.entry = {.count = 1, .reusable = true}}, SHIFT(114),
  [320] = {.entry = {.count = 1, .reusable = false}}, SHIFT(113),
  [322] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [324] = {.entry = {.count = 1, .reusable = false}}, SHIFT(111),
  [326] = {.entry = {.count = 1, .reusable = true}}, SHIFT(110),
  [328] = {.entry = {.count = 1, .reusable = true}}, SHIFT(109),
  [330] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [332] = {.entry = {.count = 1, .reusable = true}}, SHIFT(107),
  [334] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_lookup_func, 5, .production_id = 8),
  [336] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_lookup_func, 5, .production_id = 8),
  [338] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [340] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [342] = {.entry = {.count = 1, .reusable = true}}, SHIFT(102),
  [344] = {.entry = {.count = 1, .reusable = true}}, SHIFT(130),
  [346] = {.entry = {.count = 1, .reusable = false}}, SHIFT(130),
  [348] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_len_func, 4, .production_id = 5),
  [350] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_len_func, 4, .production_id = 5),
  [352] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 1),
  [354] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 1),
  [356] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [358] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [360] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [362] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(14),
  [365] = {.entry = {.count = 1, .reusable = true}}, SHIFT(89),
  [367] = {.entry = {.count = 1, .reusable = true}}, SHIFT(90),
  [369] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [371] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [373] = {.entry = {.count = 1, .reusable = true}}, SHIFT(93),
  [375] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 1),
  [377] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 2),
  [379] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 2), SHIFT_REPEAT(85),
  [382] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [384] = {.entry = {.count = 1, .reusable = true}}, SHIFT(85),
  [386] = {.entry = {.count = 1, .reusable = true}}, SHIFT(88),
  [388] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [390] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [392] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(91),
  [395] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [397] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(92),
  [400] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [402] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [404] = {.entry = {.count = 1, .reusable = true}}, SHIFT(91),
  [406] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [408] = {.entry = {.count = 1, .reusable = true}}, SHIFT(92),
  [410] = {.entry = {.count = 1, .reusable = true}}, SHIFT(96),
  [412] = {.entry = {.count = 1, .reusable = true}}, SHIFT(95),
  [414] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [416] = {.entry = {.count = 1, .reusable = true}}, SHIFT(98),
  [418] = {.entry = {.count = 1, .reusable = true}}, SHIFT(99),
  [420] = {.entry = {.count = 1, .reusable = true}}, SHIFT(145),
  [422] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [424] = {.entry = {.count = 1, .reusable = true}}, SHIFT(117),
  [426] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [428] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [430] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [432] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [434] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [436] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [438] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [440] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [442] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [444] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [446] = {.entry = {.count = 1, .reusable = true}}, SHIFT(136),
  [448] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [450] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [452] = {.entry = {.count = 1, .reusable = true}}, SHIFT(140),
  [454] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [456] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [458] = {.entry = {.count = 1, .reusable = true}}, SHIFT(127),
  [460] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [462] = {.entry = {.count = 1, .reusable = true}}, SHIFT(144),
  [464] = {.entry = {.count = 1, .reusable = true}}, SHIFT(50),
  [466] = {.entry = {.count = 1, .reusable = true}}, SHIFT(146),
  [468] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [470] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [472] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [474] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [476] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [478] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [480] = {.entry = {.count = 1, .reusable = true}}, SHIFT(104),
  [482] = {.entry = {.count = 1, .reusable = true}}, SHIFT(118),
  [484] = {.entry = {.count = 1, .reusable = true}}, SHIFT(154),
  [486] = {.entry = {.count = 1, .reusable = true}}, SHIFT(125),
  [488] = {.entry = {.count = 1, .reusable = true}}, SHIFT(135),
  [490] = {.entry = {.count = 1, .reusable = true}}, SHIFT(106),
  [492] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [494] = {.entry = {.count = 1, .reusable = true}}, SHIFT(70),
  [496] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [498] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [500] = {.entry = {.count = 1, .reusable = true}}, SHIFT(159),
  [502] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [504] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [506] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_string_field, 1),
  [508] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [510] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_map_string_array_field, 1),
  [512] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
  [514] = {.entry = {.count = 1, .reusable = true}}, SHIFT(101),
  [516] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [518] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [520] = {.entry = {.count = 1, .reusable = true}}, SHIFT(162),
  [522] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [524] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [526] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [528] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [530] = {.entry = {.count = 1, .reusable = true}}, SHIFT(163),
  [532] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [534] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [536] = {.entry = {.count = 1, .reusable = true}}, SHIFT(65),
  [538] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [540] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [542] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
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
