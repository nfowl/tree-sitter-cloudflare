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
#define STATE_COUNT 195
#define LARGE_STATE_COUNT 44
#define SYMBOL_COUNT 154
#define ALIAS_COUNT 0
#define TOKEN_COUNT 108
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 17
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
  anon_sym_len = 30,
  anon_sym_ends_with = 31,
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
  sym_ends_with_func = 123,
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
  sym__array_lhs = 138,
  sym_array_field_expansion = 139,
  sym__stringlike_field = 140,
  sym_number_field = 141,
  sym_ip_field = 142,
  sym_string_field = 143,
  sym_bytes_field = 144,
  sym_map_string_array_field = 145,
  sym_array_string_field = 146,
  sym_bool_field = 147,
  aux_sym_source_file_repeat1 = 148,
  aux_sym_ip_set_repeat1 = 149,
  aux_sym_string_set_repeat1 = 150,
  aux_sym_number_set_repeat1 = 151,
  aux_sym_string_func_repeat1 = 152,
  aux_sym_lookup_func_repeat1 = 153,
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
  [anon_sym_len] = "len",
  [anon_sym_ends_with] = "ends_with",
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
  [sym_ends_with_func] = "ends_with_func",
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
  [anon_sym_len] = anon_sym_len,
  [anon_sym_ends_with] = anon_sym_ends_with,
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
  [sym_ends_with_func] = sym_ends_with_func,
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
  [anon_sym_len] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ends_with] = {
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
  [sym_ends_with_func] = {
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
  [aux_sym_lookup_func_repeat1] = {
    .visible = false,
    .named = false,
  },
};

enum {
  field_concat = 1,
  field_field = 2,
  field_func = 3,
  field_index = 4,
  field_inner = 5,
  field_ip = 6,
  field_key = 7,
  field_keys = 8,
  field_lhs = 9,
  field_mask = 10,
  field_operator = 11,
  field_regex = 12,
  field_replacement = 13,
  field_rhs = 14,
  field_seed = 15,
  field_source = 16,
  field_value = 17,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_concat] = "concat",
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
  [1] = {.index = 0, .length = 4},
  [2] = {.index = 4, .length = 1},
  [3] = {.index = 5, .length = 3},
  [4] = {.index = 8, .length = 7},
  [5] = {.index = 15, .length = 2},
  [6] = {.index = 17, .length = 6},
  [7] = {.index = 23, .length = 5},
  [8] = {.index = 28, .length = 1},
  [9] = {.index = 29, .length = 1},
  [10] = {.index = 30, .length = 5},
  [11] = {.index = 35, .length = 1},
  [12] = {.index = 36, .length = 6},
  [13] = {.index = 42, .length = 2},
  [14] = {.index = 44, .length = 10},
  [15] = {.index = 54, .length = 8},
  [16] = {.index = 62, .length = 5},
  [17] = {.index = 67, .length = 14},
  [18] = {.index = 81, .length = 6},
  [19] = {.index = 87, .length = 6},
  [20] = {.index = 93, .length = 2},
  [21] = {.index = 95, .length = 7},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_field, 0, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_key, 0, .inherited = true},
  [4] =
    {field_inner, 1},
  [5] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [8] =
    {field_field, 0, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_key, 0, .inherited = true},
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [15] =
    {field_field, 2},
    {field_func, 0},
  [17] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
  [23] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
  [28] =
    {field_field, 2},
  [29] =
    {field_seed, 2},
  [30] =
    {field_field, 0, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_index, 2},
    {field_key, 0, .inherited = true},
  [35] =
    {field_key, 2},
  [36] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_keys, 3},
  [42] =
    {field_ip, 0},
    {field_mask, 2},
  [44] =
    {field_concat, 1},
    {field_concat, 2},
    {field_concat, 3},
    {field_concat, 4},
    {field_concat, 5},
    {field_field, 4, .inherited = true},
    {field_func, 0},
    {field_func, 4, .inherited = true},
    {field_index, 4, .inherited = true},
    {field_key, 4, .inherited = true},
  [54] =
    {field_field, 0, .inherited = true},
    {field_field, 1, .inherited = true},
    {field_func, 0, .inherited = true},
    {field_func, 1, .inherited = true},
    {field_index, 0, .inherited = true},
    {field_index, 1, .inherited = true},
    {field_key, 0, .inherited = true},
    {field_key, 1, .inherited = true},
  [62] =
    {field_field, 4, .inherited = true},
    {field_func, 0},
    {field_func, 4, .inherited = true},
    {field_index, 4, .inherited = true},
    {field_key, 4, .inherited = true},
  [67] =
    {field_concat, 1},
    {field_concat, 2},
    {field_concat, 3},
    {field_concat, 4},
    {field_concat, 5},
    {field_field, 2, .inherited = true},
    {field_field, 4, .inherited = true},
    {field_func, 0},
    {field_func, 2, .inherited = true},
    {field_func, 4, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_index, 4, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_key, 4, .inherited = true},
  [81] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_value, 4},
  [87] =
    {field_field, 2},
    {field_field, 2, .inherited = true},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
    {field_replacement, 4},
  [93] =
    {field_field, 2},
    {field_replacement, 4},
  [95] =
    {field_field, 2, .inherited = true},
    {field_func, 2, .inherited = true},
    {field_index, 2, .inherited = true},
    {field_key, 2, .inherited = true},
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
  [149] = 108,
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
  [185] = 185,
  [186] = 186,
  [187] = 187,
  [188] = 188,
  [189] = 189,
  [190] = 190,
  [191] = 191,
  [192] = 192,
  [193] = 193,
  [194] = 194,
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
      if (lookahead == 'a') ADVANCE(399);
      if (lookahead == 'c') ADVANCE(293);
      if (lookahead == 'e') ADVANCE(411);
      if (lookahead == 'f') ADVANCE(91);
      if (lookahead == 'g') ADVANCE(198);
      if (lookahead == 'h') ADVANCE(618);
      if (lookahead == 'i') ADVANCE(401);
      if (lookahead == 'l') ADVANCE(199);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(202);
      if (lookahead == 'o') ADVANCE(517);
      if (lookahead == 'r') ADVANCE(93);
      if (lookahead == 's') ADVANCE(575);
      if (lookahead == 't') ADVANCE(445);
      if (lookahead == 'u') ADVANCE(493);
      if (lookahead == 'x') ADVANCE(449);
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
      if (lookahead == 'c') ADVANCE(296);
      if (lookahead == 'e') ADVANCE(514);
      if (lookahead == 'g') ADVANCE(198);
      if (lookahead == 'h') ADVANCE(660);
      if (lookahead == 'i') ADVANCE(402);
      if (lookahead == 'l') ADVANCE(200);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(201);
      if (lookahead == 'r') ADVANCE(92);
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
      if (lookahead == 'c') ADVANCE(484);
      if (lookahead == 'e') ADVANCE(514);
      if (lookahead == 'g') ADVANCE(198);
      if (lookahead == 'i') ADVANCE(400);
      if (lookahead == 'l') ADVANCE(221);
      if (lookahead == 'm') ADVANCE(99);
      if (lookahead == 'n') ADVANCE(201);
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
      if (lookahead == '.') ADVANCE(138);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(307);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(148);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(160);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(110);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(126);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(303);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(362);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(393);
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
      if (lookahead == '.') ADVANCE(142);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(152);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(127);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(325);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(364);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(140);
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
      if (lookahead == '.') ADVANCE(579);
      END_STATE();
    case 31:
      if (lookahead == '.') ADVANCE(164);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(508);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(313);
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
      if (lookahead == '.') ADVANCE(390);
      END_STATE();
    case 41:
      if (lookahead == '.') ADVANCE(549);
      END_STATE();
    case 42:
      if (lookahead == '.') ADVANCE(602);
      END_STATE();
    case 43:
      if (lookahead == '.') ADVANCE(149);
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
      if (lookahead == '4') ADVANCE(745);
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
      if (lookahead == '_') ADVANCE(386);
      END_STATE();
    case 55:
      if (lookahead == '_') ADVANCE(363);
      END_STATE();
    case 56:
      if (lookahead == '_') ADVANCE(137);
      END_STATE();
    case 57:
      if (lookahead == '_') ADVANCE(336);
      END_STATE();
    case 58:
      if (lookahead == '_') ADVANCE(44);
      END_STATE();
    case 59:
      if (lookahead == '_') ADVANCE(557);
      END_STATE();
    case 60:
      if (lookahead == '_') ADVANCE(688);
      END_STATE();
    case 61:
      if (lookahead == '_') ADVANCE(297);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(700);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(580);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(165);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(184);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(503);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(324);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(104);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(379);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(352);
      END_STATE();
    case 71:
      if (lookahead == '_') ADVANCE(230);
      END_STATE();
    case 72:
      if (lookahead == '_') ADVANCE(593);
      END_STATE();
    case 73:
      if (lookahead == '_') ADVANCE(540);
      END_STATE();
    case 74:
      if (lookahead == '_') ADVANCE(672);
      END_STATE();
    case 75:
      if (lookahead == '_') ADVANCE(670);
      END_STATE();
    case 76:
      if (lookahead == '_') ADVANCE(351);
      END_STATE();
    case 77:
      if (lookahead == '_') ADVANCE(674);
      END_STATE();
    case 78:
      if (lookahead == '_') ADVANCE(191);
      END_STATE();
    case 79:
      if (lookahead == '_') ADVANCE(691);
      END_STATE();
    case 80:
      if (lookahead == '_') ADVANCE(298);
      END_STATE();
    case 81:
      if (lookahead == '_') ADVANCE(141);
      END_STATE();
    case 82:
      if (lookahead == '_') ADVANCE(128);
      END_STATE();
    case 83:
      if (lookahead == '_') ADVANCE(166);
      END_STATE();
    case 84:
      if (lookahead == '_') ADVANCE(604);
      END_STATE();
    case 85:
      if (lookahead == '_') ADVANCE(168);
      END_STATE();
    case 86:
      if (lookahead == '_') ADVANCE(170);
      END_STATE();
    case 87:
      if (lookahead == '_') ADVANCE(171);
      END_STATE();
    case 88:
      if (lookahead == '_') ADVANCE(605);
      END_STATE();
    case 89:
      if (lookahead == '_') ADVANCE(398);
      END_STATE();
    case 90:
      if (lookahead == '_') ADVANCE(361);
      END_STATE();
    case 91:
      if (lookahead == 'a') ADVANCE(373);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(687);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(687);
      if (lookahead == 'e') ADVANCE(306);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(295);
      if (lookahead == 'o') ADVANCE(524);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(48);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(48);
      if (lookahead == 's') ADVANCE(78);
      END_STATE();
    case 97:
      if (lookahead == 'a') ADVANCE(810);
      END_STATE();
    case 98:
      if (lookahead == 'a') ADVANCE(416);
      if (lookahead == 'b') ADVANCE(459);
      if (lookahead == 'm') ADVANCE(103);
      if (lookahead == 'o') ADVANCE(502);
      if (lookahead == 'v') ADVANCE(496);
      END_STATE();
    case 99:
      if (lookahead == 'a') ADVANCE(608);
      END_STATE();
    case 100:
      if (lookahead == 'a') ADVANCE(528);
      END_STATE();
    case 101:
      if (lookahead == 'a') ADVANCE(335);
      END_STATE();
    case 102:
      if (lookahead == 'a') ADVANCE(389);
      END_STATE();
    case 103:
      if (lookahead == 'a') ADVANCE(374);
      END_STATE();
    case 104:
      if (lookahead == 'a') ADVANCE(673);
      END_STATE();
    case 105:
      if (lookahead == 'a') ADVANCE(388);
      END_STATE();
    case 106:
      if (lookahead == 'a') ADVANCE(384);
      END_STATE();
    case 107:
      if (lookahead == 'a') ADVANCE(394);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(610);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(154);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(590);
      if (lookahead == 'c') ADVANCE(448);
      if (lookahead == 'i') ADVANCE(585);
      if (lookahead == 's') ADVANCE(663);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(194);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(195);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(380);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(420);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(651);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(612);
      if (lookahead == 'o') ADVANCE(407);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(560);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(583);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(415);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(601);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(637);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(629);
      END_STATE();
    case 123:
      if (lookahead == 'a') ADVANCE(632);
      END_STATE();
    case 124:
      if (lookahead == 'a') ADVANCE(417);
      END_STATE();
    case 125:
      if (lookahead == 'a') ADVANCE(310);
      END_STATE();
    case 126:
      if (lookahead == 'a') ADVANCE(162);
      if (lookahead == 'c') ADVANCE(489);
      if (lookahead == 'f') ADVANCE(667);
      if (lookahead == 'h') ADVANCE(242);
      if (lookahead == 'm') ADVANCE(265);
      if (lookahead == 't') ADVANCE(357);
      if (lookahead == 'u') ADVANCE(532);
      if (lookahead == 'v') ADVANCE(261);
      END_STATE();
    case 127:
      if (lookahead == 'a') ADVANCE(162);
      if (lookahead == 'c') ADVANCE(489);
      if (lookahead == 'f') ADVANCE(667);
      if (lookahead == 'h') ADVANCE(288);
      if (lookahead == 'm') ADVANCE(265);
      if (lookahead == 'u') ADVANCE(532);
      if (lookahead == 'v') ADVANCE(261);
      END_STATE();
    case 128:
      if (lookahead == 'a') ADVANCE(312);
      END_STATE();
    case 129:
      if (lookahead == 'a') ADVANCE(548);
      END_STATE();
    case 130:
      if (lookahead == 'a') ADVANCE(311);
      END_STATE();
    case 131:
      if (lookahead == 'a') ADVANCE(430);
      END_STATE();
    case 132:
      if (lookahead == 'a') ADVANCE(649);
      END_STATE();
    case 133:
      if (lookahead == 'a') ADVANCE(391);
      END_STATE();
    case 134:
      if (lookahead == 'a') ADVANCE(196);
      END_STATE();
    case 135:
      if (lookahead == 'a') ADVANCE(314);
      END_STATE();
    case 136:
      if (lookahead == 'a') ADVANCE(443);
      END_STATE();
    case 137:
      if (lookahead == 'b') ADVANCE(699);
      END_STATE();
    case 138:
      if (lookahead == 'b') ADVANCE(457);
      if (lookahead == 'c') ADVANCE(372);
      if (lookahead == 'e') ADVANCE(174);
      if (lookahead == 'h') ADVANCE(472);
      if (lookahead == 'r') ADVANCE(124);
      if (lookahead == 't') ADVANCE(321);
      if (lookahead == 'w') ADVANCE(94);
      END_STATE();
    case 139:
      if (lookahead == 'b') ADVANCE(182);
      END_STATE();
    case 140:
      if (lookahead == 'b') ADVANCE(467);
      END_STATE();
    case 141:
      if (lookahead == 'b') ADVANCE(470);
      END_STATE();
    case 142:
      if (lookahead == 'b') ADVANCE(492);
      if (lookahead == 'h') ADVANCE(472);
      if (lookahead == 'w') ADVANCE(458);
      END_STATE();
    case 143:
      if (lookahead == 'c') ADVANCE(320);
      END_STATE();
    case 144:
      if (lookahead == 'c') ADVANCE(783);
      END_STATE();
    case 145:
      if (lookahead == 'c') ADVANCE(760);
      END_STATE();
    case 146:
      if (lookahead == 'c') ADVANCE(773);
      END_STATE();
    case 147:
      if (lookahead == 'c') ADVANCE(774);
      END_STATE();
    case 148:
      if (lookahead == 'c') ADVANCE(460);
      if (lookahead == 'h') ADVANCE(475);
      if (lookahead == 'r') ADVANCE(207);
      if (lookahead == 'u') ADVANCE(600);
      if (lookahead == 'x') ADVANCE(61);
      END_STATE();
    case 149:
      if (lookahead == 'c') ADVANCE(460);
      if (lookahead == 'h') ADVANCE(475);
      if (lookahead == 'r') ADVANCE(291);
      if (lookahead == 'u') ADVANCE(600);
      if (lookahead == 'x') ADVANCE(61);
      END_STATE();
    case 150:
      if (lookahead == 'c') ADVANCE(145);
      END_STATE();
    case 151:
      if (lookahead == 'c') ADVANCE(473);
      END_STATE();
    case 152:
      if (lookahead == 'c') ADVANCE(448);
      if (lookahead == 's') ADVANCE(663);
      END_STATE();
    case 153:
      if (lookahead == 'c') ADVANCE(8);
      END_STATE();
    case 154:
      if (lookahead == 'c') ADVANCE(212);
      END_STATE();
    case 155:
      if (lookahead == 'c') ADVANCE(214);
      END_STATE();
    case 156:
      if (lookahead == 'c') ADVANCE(657);
      END_STATE();
    case 157:
      if (lookahead == 'c') ADVANCE(236);
      END_STATE();
    case 158:
      if (lookahead == 'c') ADVANCE(108);
      END_STATE();
    case 159:
      if (lookahead == 'c') ADVANCE(108);
      if (lookahead == 't') ADVANCE(101);
      END_STATE();
    case 160:
      if (lookahead == 'c') ADVANCE(341);
      if (lookahead == 'l') ADVANCE(116);
      if (lookahead == 'm') ADVANCE(272);
      if (lookahead == 'p') ADVANCE(478);
      END_STATE();
    case 161:
      if (lookahead == 'c') ADVANCE(481);
      END_STATE();
    case 162:
      if (lookahead == 'c') ADVANCE(157);
      END_STATE();
    case 163:
      if (lookahead == 'c') ADVANCE(132);
      END_STATE();
    case 164:
      if (lookahead == 'c') ADVANCE(277);
      END_STATE();
    case 165:
      if (lookahead == 'c') ADVANCE(381);
      END_STATE();
    case 166:
      if (lookahead == 'c') ADVANCE(479);
      END_STATE();
    case 167:
      if (lookahead == 'c') ADVANCE(482);
      END_STATE();
    case 168:
      if (lookahead == 'c') ADVANCE(480);
      END_STATE();
    case 169:
      if (lookahead == 'c') ADVANCE(486);
      END_STATE();
    case 170:
      if (lookahead == 'c') ADVANCE(483);
      END_STATE();
    case 171:
      if (lookahead == 'c') ADVANCE(485);
      END_STATE();
    case 172:
      if (lookahead == 'd') ADVANCE(707);
      END_STATE();
    case 173:
      if (lookahead == 'd') ADVANCE(577);
      END_STATE();
    case 174:
      if (lookahead == 'd') ADVANCE(309);
      END_STATE();
    case 175:
      if (lookahead == 'd') ADVANCE(812);
      END_STATE();
    case 176:
      if (lookahead == 'd') ADVANCE(789);
      END_STATE();
    case 177:
      if (lookahead == 'd') ADVANCE(826);
      END_STATE();
    case 178:
      if (lookahead == 'd') ADVANCE(824);
      END_STATE();
    case 179:
      if (lookahead == 'd') ADVANCE(825);
      END_STATE();
    case 180:
      if (lookahead == 'd') ADVANCE(822);
      END_STATE();
    case 181:
      if (lookahead == 'd') ADVANCE(682);
      END_STATE();
    case 182:
      if (lookahead == 'd') ADVANCE(334);
      END_STATE();
    case 183:
      if (lookahead == 'd') ADVANCE(451);
      END_STATE();
    case 184:
      if (lookahead == 'd') ADVANCE(222);
      END_STATE();
    case 185:
      if (lookahead == 'd') ADVANCE(208);
      END_STATE();
    case 186:
      if (lookahead == 'd') ADVANCE(69);
      END_STATE();
    case 187:
      if (lookahead == 'd') ADVANCE(81);
      END_STATE();
    case 188:
      if (lookahead == 'd') ADVANCE(234);
      END_STATE();
    case 189:
      if (lookahead == 'd') ADVANCE(215);
      END_STATE();
    case 190:
      if (lookahead == 'd') ADVANCE(216);
      END_STATE();
    case 191:
      if (lookahead == 'd') ADVANCE(280);
      END_STATE();
    case 192:
      if (lookahead == 'd') ADVANCE(219);
      END_STATE();
    case 193:
      if (lookahead == 'd') ADVANCE(220);
      END_STATE();
    case 194:
      if (lookahead == 'd') ADVANCE(121);
      END_STATE();
    case 195:
      if (lookahead == 'd') ADVANCE(263);
      END_STATE();
    case 196:
      if (lookahead == 'd') ADVANCE(270);
      END_STATE();
    case 197:
      if (lookahead == 'd') ADVANCE(80);
      END_STATE();
    case 198:
      if (lookahead == 'e') ADVANCE(721);
      if (lookahead == 't') ADVANCE(720);
      END_STATE();
    case 199:
      if (lookahead == 'e') ADVANCE(719);
      if (lookahead == 'o') ADVANCE(446);
      if (lookahead == 't') ADVANCE(717);
      END_STATE();
    case 200:
      if (lookahead == 'e') ADVANCE(719);
      if (lookahead == 't') ADVANCE(717);
      END_STATE();
    case 201:
      if (lookahead == 'e') ADVANCE(716);
      END_STATE();
    case 202:
      if (lookahead == 'e') ADVANCE(716);
      if (lookahead == 'o') ADVANCE(609);
      END_STATE();
    case 203:
      if (lookahead == 'e') ADVANCE(692);
      END_STATE();
    case 204:
      if (lookahead == 'e') ADVANCE(749);
      END_STATE();
    case 205:
      if (lookahead == 'e') ADVANCE(750);
      END_STATE();
    case 206:
      if (lookahead == 'e') ADVANCE(760);
      END_STATE();
    case 207:
      if (lookahead == 'e') ADVANCE(299);
      END_STATE();
    case 208:
      if (lookahead == 'e') ADVANCE(744);
      END_STATE();
    case 209:
      if (lookahead == 'e') ADVANCE(785);
      END_STATE();
    case 210:
      if (lookahead == 'e') ADVANCE(516);
      END_STATE();
    case 211:
      if (lookahead == 'e') ADVANCE(779);
      END_STATE();
    case 212:
      if (lookahead == 'e') ADVANCE(739);
      END_STATE();
    case 213:
      if (lookahead == 'e') ADVANCE(778);
      END_STATE();
    case 214:
      if (lookahead == 'e') ADVANCE(782);
      END_STATE();
    case 215:
      if (lookahead == 'e') ADVANCE(800);
      END_STATE();
    case 216:
      if (lookahead == 'e') ADVANCE(799);
      END_STATE();
    case 217:
      if (lookahead == 'e') ADVANCE(776);
      END_STATE();
    case 218:
      if (lookahead == 'e') ADVANCE(811);
      END_STATE();
    case 219:
      if (lookahead == 'e') ADVANCE(803);
      END_STATE();
    case 220:
      if (lookahead == 'e') ADVANCE(804);
      END_STATE();
    case 221:
      if (lookahead == 'e') ADVANCE(718);
      if (lookahead == 't') ADVANCE(717);
      END_STATE();
    case 222:
      if (lookahead == 'e') ADVANCE(151);
      END_STATE();
    case 223:
      if (lookahead == 'e') ADVANCE(519);
      END_STATE();
    case 224:
      if (lookahead == 'e') ADVANCE(455);
      END_STATE();
    case 225:
      if (lookahead == 'e') ADVANCE(498);
      END_STATE();
    case 226:
      if (lookahead == 'e') ADVANCE(566);
      END_STATE();
    case 227:
      if (lookahead == 'e') ADVANCE(685);
      END_STATE();
    case 228:
      if (lookahead == 'e') ADVANCE(520);
      END_STATE();
    case 229:
      if (lookahead == 'e') ADVANCE(42);
      END_STATE();
    case 230:
      if (lookahead == 'e') ADVANCE(671);
      END_STATE();
    case 231:
      if (lookahead == 'e') ADVANCE(421);
      END_STATE();
    case 232:
      if (lookahead == 'e') ADVANCE(175);
      END_STATE();
    case 233:
      if (lookahead == 'e') ADVANCE(423);
      END_STATE();
    case 234:
      if (lookahead == 'e') ADVANCE(197);
      END_STATE();
    case 235:
      if (lookahead == 'e') ADVANCE(56);
      END_STATE();
    case 236:
      if (lookahead == 'e') ADVANCE(509);
      END_STATE();
    case 237:
      if (lookahead == 'e') ADVANCE(533);
      END_STATE();
    case 238:
      if (lookahead == 'e') ADVANCE(568);
      END_STATE();
    case 239:
      if (lookahead == 'e') ADVANCE(156);
      END_STATE();
    case 240:
      if (lookahead == 'e') ADVANCE(534);
      END_STATE();
    case 241:
      if (lookahead == 'e') ADVANCE(40);
      END_STATE();
    case 242:
      if (lookahead == 'e') ADVANCE(112);
      END_STATE();
    case 243:
      if (lookahead == 'e') ADVANCE(562);
      END_STATE();
    case 244:
      if (lookahead == 'e') ADVANCE(565);
      END_STATE();
    case 245:
      if (lookahead == 'e') ADVANCE(146);
      END_STATE();
    case 246:
      if (lookahead == 'e') ADVANCE(105);
      END_STATE();
    case 247:
      if (lookahead == 'e') ADVANCE(186);
      END_STATE();
    case 248:
      if (lookahead == 'e') ADVANCE(147);
      END_STATE();
    case 249:
      if (lookahead == 'e') ADVANCE(177);
      END_STATE();
    case 250:
      if (lookahead == 'e') ADVANCE(626);
      END_STATE();
    case 251:
      if (lookahead == 'e') ADVANCE(526);
      END_STATE();
    case 252:
      if (lookahead == 'e') ADVANCE(178);
      END_STATE();
    case 253:
      if (lookahead == 'e') ADVANCE(179);
      END_STATE();
    case 254:
      if (lookahead == 'e') ADVANCE(570);
      END_STATE();
    case 255:
      if (lookahead == 'e') ADVANCE(522);
      END_STATE();
    case 256:
      if (lookahead == 'e') ADVANCE(180);
      END_STATE();
    case 257:
      if (lookahead == 'e') ADVANCE(521);
      END_STATE();
    case 258:
      if (lookahead == 'e') ADVANCE(572);
      END_STATE();
    case 259:
      if (lookahead == 'e') ADVANCE(573);
      END_STATE();
    case 260:
      if (lookahead == 'e') ADVANCE(574);
      END_STATE();
    case 261:
      if (lookahead == 'e') ADVANCE(539);
      END_STATE();
    case 262:
      if (lookahead == 'e') ADVANCE(404);
      if (lookahead == 'o') ADVANCE(446);
      END_STATE();
    case 263:
      if (lookahead == 'e') ADVANCE(546);
      END_STATE();
    case 264:
      if (lookahead == 'e') ADVANCE(634);
      END_STATE();
    case 265:
      if (lookahead == 'e') ADVANCE(625);
      END_STATE();
    case 266:
      if (lookahead == 'e') ADVANCE(232);
      END_STATE();
    case 267:
      if (lookahead == 'e') ADVANCE(545);
      END_STATE();
    case 268:
      if (lookahead == 'e') ADVANCE(529);
      END_STATE();
    case 269:
      if (lookahead == 'e') ADVANCE(530);
      END_STATE();
    case 270:
      if (lookahead == 'e') ADVANCE(550);
      END_STATE();
    case 271:
      if (lookahead == 'e') ADVANCE(131);
      END_STATE();
    case 272:
      if (lookahead == 'e') ADVANCE(641);
      END_STATE();
    case 273:
      if (lookahead == 'e') ADVANCE(428);
      END_STATE();
    case 274:
      if (lookahead == 'e') ADVANCE(542);
      END_STATE();
    case 275:
      if (lookahead == 'e') ADVANCE(187);
      END_STATE();
    case 276:
      if (lookahead == 'e') ADVANCE(115);
      END_STATE();
    case 277:
      if (lookahead == 'e') ADVANCE(554);
      END_STATE();
    case 278:
      if (lookahead == 'e') ADVANCE(395);
      END_STATE();
    case 279:
      if (lookahead == 'e') ADVANCE(431);
      END_STATE();
    case 280:
      if (lookahead == 'e') ADVANCE(648);
      END_STATE();
    case 281:
      if (lookahead == 'e') ADVANCE(432);
      END_STATE();
    case 282:
      if (lookahead == 'e') ADVANCE(592);
      END_STATE();
    case 283:
      if (lookahead == 'e') ADVANCE(433);
      END_STATE();
    case 284:
      if (lookahead == 'e') ADVANCE(594);
      END_STATE();
    case 285:
      if (lookahead == 'e') ADVANCE(434);
      END_STATE();
    case 286:
      if (lookahead == 'e') ADVANCE(595);
      END_STATE();
    case 287:
      if (lookahead == 'e') ADVANCE(596);
      END_STATE();
    case 288:
      if (lookahead == 'e') ADVANCE(134);
      END_STATE();
    case 289:
      if (lookahead == 'e') ADVANCE(564);
      END_STATE();
    case 290:
      if (lookahead == 'e') ADVANCE(396);
      END_STATE();
    case 291:
      if (lookahead == 'e') ADVANCE(300);
      END_STATE();
    case 292:
      if (lookahead == 'e') ADVANCE(488);
      END_STATE();
    case 293:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(403);
      END_STATE();
    case 294:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(441);
      END_STATE();
    case 295:
      if (lookahead == 'f') ADVANCE(30);
      END_STATE();
    case 296:
      if (lookahead == 'f') ADVANCE(19);
      if (lookahead == 'o') ADVANCE(403);
      END_STATE();
    case 297:
      if (lookahead == 'f') ADVANCE(462);
      END_STATE();
    case 298:
      if (lookahead == 'f') ADVANCE(469);
      END_STATE();
    case 299:
      if (lookahead == 'f') ADVANCE(243);
      if (lookahead == 'q') ADVANCE(668);
      END_STATE();
    case 300:
      if (lookahead == 'f') ADVANCE(243);
      if (lookahead == 'q') ADVANCE(680);
      END_STATE();
    case 301:
      if (lookahead == 'f') ADVANCE(355);
      END_STATE();
    case 302:
      if (lookahead == 'f') ADVANCE(348);
      END_STATE();
    case 303:
      if (lookahead == 'f') ADVANCE(681);
      if (lookahead == 'u') ADVANCE(538);
      END_STATE();
    case 304:
      if (lookahead == 'g') ADVANCE(742);
      END_STATE();
    case 305:
      if (lookahead == 'g') ADVANCE(737);
      END_STATE();
    case 306:
      if (lookahead == 'g') ADVANCE(203);
      if (lookahead == 'm') ADVANCE(447);
      END_STATE();
    case 307:
      if (lookahead == 'g') ADVANCE(224);
      if (lookahead == 's') ADVANCE(525);
      END_STATE();
    case 308:
      if (lookahead == 'g') ADVANCE(679);
      END_STATE();
    case 309:
      if (lookahead == 'g') ADVANCE(229);
      END_STATE();
    case 310:
      if (lookahead == 'g') ADVANCE(278);
      END_STATE();
    case 311:
      if (lookahead == 'g') ADVANCE(260);
      END_STATE();
    case 312:
      if (lookahead == 'g') ADVANCE(279);
      END_STATE();
    case 313:
      if (lookahead == 'g') ADVANCE(292);
      if (lookahead == 's') ADVANCE(541);
      END_STATE();
    case 314:
      if (lookahead == 'g') ADVANCE(290);
      END_STATE();
    case 315:
      if (lookahead == 'h') ADVANCE(736);
      END_STATE();
    case 316:
      if (lookahead == 'h') ADVANCE(741);
      END_STATE();
    case 317:
      if (lookahead == 'h') ADVANCE(791);
      END_STATE();
    case 318:
      if (lookahead == 'h') ADVANCE(807);
      END_STATE();
    case 319:
      if (lookahead == 'h') ADVANCE(809);
      END_STATE();
    case 320:
      if (lookahead == 'h') ADVANCE(226);
      END_STATE();
    case 321:
      if (lookahead == 'h') ADVANCE(535);
      if (lookahead == 'l') ADVANCE(581);
      END_STATE();
    case 322:
      if (lookahead == 'h') ADVANCE(461);
      END_STATE();
    case 323:
      if (lookahead == 'h') ADVANCE(31);
      END_STATE();
    case 324:
      if (lookahead == 'h') ADVANCE(118);
      END_STATE();
    case 325:
      if (lookahead == 'h') ADVANCE(655);
      END_STATE();
    case 326:
      if (lookahead == 'i') ADVANCE(701);
      END_STATE();
    case 327:
      if (lookahead == 'i') ADVANCE(790);
      END_STATE();
    case 328:
      if (lookahead == 'i') ADVANCE(780);
      END_STATE();
    case 329:
      if (lookahead == 'i') ADVANCE(806);
      END_STATE();
    case 330:
      if (lookahead == 'i') ADVANCE(788);
      END_STATE();
    case 331:
      if (lookahead == 'i') ADVANCE(805);
      END_STATE();
    case 332:
      if (lookahead == 'i') ADVANCE(181);
      END_STATE();
    case 333:
      if (lookahead == 'i') ADVANCE(301);
      END_STATE();
    case 334:
      if (lookahead == 'i') ADVANCE(684);
      END_STATE();
    case 335:
      if (lookahead == 'i') ADVANCE(419);
      END_STATE();
    case 336:
      if (lookahead == 'i') ADVANCE(494);
      if (lookahead == 'p') ADVANCE(471);
      END_STATE();
    case 337:
      if (lookahead == 'i') ADVANCE(233);
      END_STATE();
    case 338:
      if (lookahead == 'i') ADVANCE(412);
      END_STATE();
    case 339:
      if (lookahead == 'i') ADVANCE(620);
      END_STATE();
    case 340:
      if (lookahead == 'i') ADVANCE(587);
      END_STATE();
    case 341:
      if (lookahead == 'i') ADVANCE(621);
      END_STATE();
    case 342:
      if (lookahead == 'i') ADVANCE(413);
      END_STATE();
    case 343:
      if (lookahead == 'i') ADVANCE(477);
      END_STATE();
    case 344:
      if (lookahead == 'i') ADVANCE(622);
      END_STATE();
    case 345:
      if (lookahead == 'i') ADVANCE(209);
      END_STATE();
    case 346:
      if (lookahead == 'i') ADVANCE(244);
      END_STATE();
    case 347:
      if (lookahead == 'i') ADVANCE(254);
      END_STATE();
    case 348:
      if (lookahead == 'i') ADVANCE(253);
      END_STATE();
    case 349:
      if (lookahead == 'i') ADVANCE(499);
      END_STATE();
    case 350:
      if (lookahead == 'i') ADVANCE(440);
      END_STATE();
    case 351:
      if (lookahead == 'i') ADVANCE(425);
      END_STATE();
    case 352:
      if (lookahead == 'i') ADVANCE(606);
      END_STATE();
    case 353:
      if (lookahead == 'i') ADVANCE(273);
      END_STATE();
    case 354:
      if (lookahead == 'i') ADVANCE(465);
      END_STATE();
    case 355:
      if (lookahead == 'i') ADVANCE(275);
      END_STATE();
    case 356:
      if (lookahead == 'i') ADVANCE(466);
      END_STATE();
    case 357:
      if (lookahead == 'i') ADVANCE(397);
      END_STATE();
    case 358:
      if (lookahead == 'i') ADVANCE(468);
      END_STATE();
    case 359:
      if (lookahead == 'i') ADVANCE(505);
      END_STATE();
    case 360:
      if (lookahead == 'i') ADVANCE(302);
      END_STATE();
    case 361:
      if (lookahead == 'i') ADVANCE(607);
      END_STATE();
    case 362:
      if (lookahead == 'j') ADVANCE(96);
      if (lookahead == 's') ADVANCE(169);
      if (lookahead == 'v') ADVANCE(267);
      END_STATE();
    case 363:
      if (lookahead == 'j') ADVANCE(584);
      END_STATE();
    case 364:
      if (lookahead == 'j') ADVANCE(95);
      END_STATE();
    case 365:
      if (lookahead == 'k') ADVANCE(664);
      END_STATE();
    case 366:
      if (lookahead == 'k') ADVANCE(252);
      END_STATE();
    case 367:
      if (lookahead == 'k') ADVANCE(345);
      END_STATE();
    case 368:
      if (lookahead == 'k') ADVANCE(237);
      END_STATE();
    case 369:
      if (lookahead == 'k') ADVANCE(347);
      END_STATE();
    case 370:
      if (lookahead == 'l') ADVANCE(820);
      END_STATE();
    case 371:
      if (lookahead == 'l') ADVANCE(65);
      END_STATE();
    case 372:
      if (lookahead == 'l') ADVANCE(337);
      END_STATE();
    case 373:
      if (lookahead == 'l') ADVANCE(578);
      END_STATE();
    case 374:
      if (lookahead == 'l') ADVANCE(689);
      END_STATE();
    case 375:
      if (lookahead == 'l') ADVANCE(109);
      END_STATE();
    case 376:
      if (lookahead == 'l') ADVANCE(328);
      END_STATE();
    case 377:
      if (lookahead == 'l') ADVANCE(74);
      END_STATE();
    case 378:
      if (lookahead == 'l') ADVANCE(377);
      END_STATE();
    case 379:
      if (lookahead == 'l') ADVANCE(119);
      END_STATE();
    case 380:
      if (lookahead == 'l') ADVANCE(675);
      END_STATE();
    case 381:
      if (lookahead == 'l') ADVANCE(353);
      END_STATE();
    case 382:
      if (lookahead == 'l') ADVANCE(77);
      END_STATE();
    case 383:
      if (lookahead == 'l') ADVANCE(382);
      END_STATE();
    case 384:
      if (lookahead == 'l') ADVANCE(85);
      END_STATE();
    case 385:
      if (lookahead == 'm') ADVANCE(775);
      END_STATE();
    case 386:
      if (lookahead == 'm') ADVANCE(114);
      END_STATE();
    case 387:
      if (lookahead == 'm') ADVANCE(326);
      END_STATE();
    case 388:
      if (lookahead == 'm') ADVANCE(62);
      END_STATE();
    case 389:
      if (lookahead == 'm') ADVANCE(241);
      END_STATE();
    case 390:
      if (lookahead == 'm') ADVANCE(264);
      END_STATE();
    case 391:
      if (lookahead == 'm') ADVANCE(258);
      END_STATE();
    case 392:
      if (lookahead == 'm') ADVANCE(72);
      END_STATE();
    case 393:
      if (lookahead == 'm') ADVANCE(597);
      if (lookahead == 's') ADVANCE(245);
      END_STATE();
    case 394:
      if (lookahead == 'm') ADVANCE(504);
      END_STATE();
    case 395:
      if (lookahead == 'm') ADVANCE(281);
      END_STATE();
    case 396:
      if (lookahead == 'm') ADVANCE(285);
      END_STATE();
    case 397:
      if (lookahead == 'm') ADVANCE(286);
      END_STATE();
    case 398:
      if (lookahead == 'm') ADVANCE(136);
      END_STATE();
    case 399:
      if (lookahead == 'n') ADVANCE(172);
      END_STATE();
    case 400:
      if (lookahead == 'n') ADVANCE(705);
      END_STATE();
    case 401:
      if (lookahead == 'n') ADVANCE(705);
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 402:
      if (lookahead == 'n') ADVANCE(705);
      if (lookahead == 'p') ADVANCE(33);
      END_STATE();
    case 403:
      if (lookahead == 'n') ADVANCE(159);
      END_STATE();
    case 404:
      if (lookahead == 'n') ADVANCE(735);
      END_STATE();
    case 405:
      if (lookahead == 'n') ADVANCE(760);
      END_STATE();
    case 406:
      if (lookahead == 'n') ADVANCE(698);
      END_STATE();
    case 407:
      if (lookahead == 'n') ADVANCE(797);
      END_STATE();
    case 408:
      if (lookahead == 'n') ADVANCE(794);
      END_STATE();
    case 409:
      if (lookahead == 'n') ADVANCE(819);
      END_STATE();
    case 410:
      if (lookahead == 'n') ADVANCE(173);
      END_STATE();
    case 411:
      if (lookahead == 'n') ADVANCE(173);
      if (lookahead == 'q') ADVANCE(715);
      END_STATE();
    case 412:
      if (lookahead == 'n') ADVANCE(304);
      END_STATE();
    case 413:
      if (lookahead == 'n') ADVANCE(305);
      END_STATE();
    case 414:
      if (lookahead == 'n') ADVANCE(665);
      END_STATE();
    case 415:
      if (lookahead == 'n') ADVANCE(308);
      END_STATE();
    case 416:
      if (lookahead == 'n') ADVANCE(456);
      END_STATE();
    case 417:
      if (lookahead == 'n') ADVANCE(183);
      END_STATE();
    case 418:
      if (lookahead == 'n') ADVANCE(102);
      END_STATE();
    case 419:
      if (lookahead == 'n') ADVANCE(567);
      END_STATE();
    case 420:
      if (lookahead == 'n') ADVANCE(125);
      END_STATE();
    case 421:
      if (lookahead == 'n') ADVANCE(66);
      END_STATE();
    case 422:
      if (lookahead == 'n') ADVANCE(163);
      END_STATE();
    case 423:
      if (lookahead == 'n') ADVANCE(631);
      END_STATE();
    case 424:
      if (lookahead == 'n') ADVANCE(250);
      END_STATE();
    case 425:
      if (lookahead == 'n') ADVANCE(71);
      END_STATE();
    case 426:
      if (lookahead == 'n') ADVANCE(32);
      END_STATE();
    case 427:
      if (lookahead == 'n') ADVANCE(58);
      END_STATE();
    case 428:
      if (lookahead == 'n') ADVANCE(639);
      END_STATE();
    case 429:
      if (lookahead == 'n') ADVANCE(653);
      if (lookahead == 'u') ADVANCE(439);
      END_STATE();
    case 430:
      if (lookahead == 'n') ADVANCE(75);
      END_STATE();
    case 431:
      if (lookahead == 'n') ADVANCE(614);
      END_STATE();
    case 432:
      if (lookahead == 'n') ADVANCE(638);
      END_STATE();
    case 433:
      if (lookahead == 'n') ADVANCE(615);
      END_STATE();
    case 434:
      if (lookahead == 'n') ADVANCE(646);
      END_STATE();
    case 435:
      if (lookahead == 'n') ADVANCE(623);
      END_STATE();
    case 436:
      if (lookahead == 'n') ADVANCE(218);
      END_STATE();
    case 437:
      if (lookahead == 'n') ADVANCE(133);
      if (lookahead == 't') ADVANCE(531);
      if (lookahead == 'v') ADVANCE(113);
      END_STATE();
    case 438:
      if (lookahead == 'n') ADVANCE(133);
      if (lookahead == 'v') ADVANCE(113);
      END_STATE();
    case 439:
      if (lookahead == 'n') ADVANCE(642);
      END_STATE();
    case 440:
      if (lookahead == 'n') ADVANCE(283);
      END_STATE();
    case 441:
      if (lookahead == 'n') ADVANCE(158);
      END_STATE();
    case 442:
      if (lookahead == 'n') ADVANCE(356);
      END_STATE();
    case 443:
      if (lookahead == 'n') ADVANCE(135);
      END_STATE();
    case 444:
      if (lookahead == 'n') ADVANCE(88);
      END_STATE();
    case 445:
      if (lookahead == 'o') ADVANCE(63);
      if (lookahead == 'r') ADVANCE(662);
      END_STATE();
    case 446:
      if (lookahead == 'o') ADVANCE(365);
      if (lookahead == 'w') ADVANCE(223);
      END_STATE();
    case 447:
      if (lookahead == 'o') ADVANCE(683);
      END_STATE();
    case 448:
      if (lookahead == 'o') ADVANCE(429);
      END_STATE();
    case 449:
      if (lookahead == 'o') ADVANCE(518);
      END_STATE();
    case 450:
      if (lookahead == 'o') ADVANCE(693);
      END_STATE();
    case 451:
      if (lookahead == 'o') ADVANCE(392);
      END_STATE();
    case 452:
      if (lookahead == 'o') ADVANCE(367);
      END_STATE();
    case 453:
      if (lookahead == 'o') ADVANCE(609);
      END_STATE();
    case 454:
      if (lookahead == 'o') ADVANCE(366);
      END_STATE();
    case 455:
      if (lookahead == 'o') ADVANCE(349);
      END_STATE();
    case 456:
      if (lookahead == 'o') ADVANCE(406);
      END_STATE();
    case 457:
      if (lookahead == 'o') ADVANCE(624);
      END_STATE();
    case 458:
      if (lookahead == 'o') ADVANCE(524);
      END_STATE();
    case 459:
      if (lookahead == 'o') ADVANCE(628);
      END_STATE();
    case 460:
      if (lookahead == 'o') ADVANCE(452);
      END_STATE();
    case 461:
      if (lookahead == 'o') ADVANCE(176);
      END_STATE();
    case 462:
      if (lookahead == 'o') ADVANCE(563);
      END_STATE();
    case 463:
      if (lookahead == 'o') ADVANCE(83);
      END_STATE();
    case 464:
      if (lookahead == 'o') ADVANCE(444);
      END_STATE();
    case 465:
      if (lookahead == 'o') ADVANCE(408);
      END_STATE();
    case 466:
      if (lookahead == 'o') ADVANCE(409);
      END_STATE();
    case 467:
      if (lookahead == 'o') ADVANCE(613);
      END_STATE();
    case 468:
      if (lookahead == 'o') ADVANCE(426);
      END_STATE();
    case 469:
      if (lookahead == 'o') ADVANCE(523);
      END_STATE();
    case 470:
      if (lookahead == 'o') ADVANCE(617);
      END_STATE();
    case 471:
      if (lookahead == 'o') ADVANCE(553);
      END_STATE();
    case 472:
      if (lookahead == 'o') ADVANCE(582);
      END_STATE();
    case 473:
      if (lookahead == 'o') ADVANCE(185);
      END_STATE();
    case 474:
      if (lookahead == 'o') ADVANCE(506);
      END_STATE();
    case 475:
      if (lookahead == 'o') ADVANCE(589);
      END_STATE();
    case 476:
      if (lookahead == 'o') ADVANCE(436);
      END_STATE();
    case 477:
      if (lookahead == 'o') ADVANCE(427);
      END_STATE();
    case 478:
      if (lookahead == 'o') ADVANCE(591);
      END_STATE();
    case 479:
      if (lookahead == 'o') ADVANCE(189);
      END_STATE();
    case 480:
      if (lookahead == 'o') ADVANCE(190);
      END_STATE();
    case 481:
      if (lookahead == 'o') ADVANCE(551);
      END_STATE();
    case 482:
      if (lookahead == 'o') ADVANCE(552);
      END_STATE();
    case 483:
      if (lookahead == 'o') ADVANCE(192);
      END_STATE();
    case 484:
      if (lookahead == 'o') ADVANCE(435);
      END_STATE();
    case 485:
      if (lookahead == 'o') ADVANCE(193);
      END_STATE();
    case 486:
      if (lookahead == 'o') ADVANCE(556);
      END_STATE();
    case 487:
      if (lookahead == 'o') ADVANCE(369);
      END_STATE();
    case 488:
      if (lookahead == 'o') ADVANCE(359);
      END_STATE();
    case 489:
      if (lookahead == 'o') ADVANCE(487);
      END_STATE();
    case 490:
      if (lookahead == 'o') ADVANCE(86);
      END_STATE();
    case 491:
      if (lookahead == 'o') ADVANCE(87);
      END_STATE();
    case 492:
      if (lookahead == 'o') ADVANCE(661);
      END_STATE();
    case 493:
      if (lookahead == 'p') ADVANCE(507);
      if (lookahead == 'r') ADVANCE(371);
      if (lookahead == 'u') ADVANCE(332);
      END_STATE();
    case 494:
      if (lookahead == 'p') ADVANCE(784);
      END_STATE();
    case 495:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 496:
      if (lookahead == 'p') ADVANCE(405);
      END_STATE();
    case 497:
      if (lookahead == 'p') ADVANCE(7);
      END_STATE();
    case 498:
      if (lookahead == 'p') ADVANCE(375);
      END_STATE();
    case 499:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 500:
      if (lookahead == 'p') ADVANCE(41);
      END_STATE();
    case 501:
      if (lookahead == 'p') ADVANCE(55);
      END_STATE();
    case 502:
      if (lookahead == 'p') ADVANCE(231);
      END_STATE();
    case 503:
      if (lookahead == 'p') ADVANCE(536);
      END_STATE();
    case 504:
      if (lookahead == 'p') ADVANCE(13);
      END_STATE();
    case 505:
      if (lookahead == 'p') ADVANCE(20);
      END_STATE();
    case 506:
      if (lookahead == 'p') ADVANCE(271);
      END_STATE();
    case 507:
      if (lookahead == 'p') ADVANCE(228);
      END_STATE();
    case 508:
      if (lookahead == 'p') ADVANCE(120);
      END_STATE();
    case 509:
      if (lookahead == 'p') ADVANCE(647);
      END_STATE();
    case 510:
      if (lookahead == 'p') ADVANCE(122);
      if (lookahead == 'q') ADVANCE(676);
      END_STATE();
    case 511:
      if (lookahead == 'p') ADVANCE(123);
      if (lookahead == 'q') ADVANCE(677);
      END_STATE();
    case 512:
      if (lookahead == 'p') ADVANCE(599);
      END_STATE();
    case 513:
      if (lookahead == 'p') ADVANCE(43);
      END_STATE();
    case 514:
      if (lookahead == 'q') ADVANCE(715);
      END_STATE();
    case 515:
      if (lookahead == 'q') ADVANCE(376);
      END_STATE();
    case 516:
      if (lookahead == 'q') ADVANCE(678);
      END_STATE();
    case 517:
      if (lookahead == 'r') ADVANCE(710);
      END_STATE();
    case 518:
      if (lookahead == 'r') ADVANCE(708);
      END_STATE();
    case 519:
      if (lookahead == 'r') ADVANCE(738);
      END_STATE();
    case 520:
      if (lookahead == 'r') ADVANCE(743);
      END_STATE();
    case 521:
      if (lookahead == 'r') ADVANCE(760);
      END_STATE();
    case 522:
      if (lookahead == 'r') ADVANCE(787);
      END_STATE();
    case 523:
      if (lookahead == 'r') ADVANCE(795);
      END_STATE();
    case 524:
      if (lookahead == 'r') ADVANCE(368);
      END_STATE();
    case 525:
      if (lookahead == 'r') ADVANCE(144);
      END_STATE();
    case 526:
      if (lookahead == 'r') ADVANCE(686);
      END_STATE();
    case 527:
      if (lookahead == 'r') ADVANCE(695);
      END_STATE();
    case 528:
      if (lookahead == 'r') ADVANCE(658);
      END_STATE();
    case 529:
      if (lookahead == 'r') ADVANCE(696);
      END_STATE();
    case 530:
      if (lookahead == 'r') ADVANCE(697);
      END_STATE();
    case 531:
      if (lookahead == 'r') ADVANCE(669);
      END_STATE();
    case 532:
      if (lookahead == 'r') ADVANCE(327);
      END_STATE();
    case 533:
      if (lookahead == 'r') ADVANCE(39);
      END_STATE();
    case 534:
      if (lookahead == 'r') ADVANCE(82);
      END_STATE();
    case 535:
      if (lookahead == 'r') ADVANCE(276);
      END_STATE();
    case 536:
      if (lookahead == 'r') ADVANCE(450);
      END_STATE();
    case 537:
      if (lookahead == 'r') ADVANCE(463);
      END_STATE();
    case 538:
      if (lookahead == 'r') ADVANCE(329);
      END_STATE();
    case 539:
      if (lookahead == 'r') ADVANCE(586);
      END_STATE();
    case 540:
      if (lookahead == 'r') ADVANCE(225);
      END_STATE();
    case 541:
      if (lookahead == 'r') ADVANCE(153);
      END_STATE();
    case 542:
      if (lookahead == 'r') ADVANCE(57);
      END_STATE();
    case 543:
      if (lookahead == 'r') ADVANCE(330);
      END_STATE();
    case 544:
      if (lookahead == 'r') ADVANCE(474);
      END_STATE();
    case 545:
      if (lookahead == 'r') ADVANCE(333);
      END_STATE();
    case 546:
      if (lookahead == 'r') ADVANCE(571);
      END_STATE();
    case 547:
      if (lookahead == 'r') ADVANCE(331);
      END_STATE();
    case 548:
      if (lookahead == 'r') ADVANCE(206);
      END_STATE();
    case 549:
      if (lookahead == 'r') ADVANCE(210);
      END_STATE();
    case 550:
      if (lookahead == 'r') ADVANCE(576);
      END_STATE();
    case 551:
      if (lookahead == 'r') ADVANCE(211);
      END_STATE();
    case 552:
      if (lookahead == 'r') ADVANCE(213);
      END_STATE();
    case 553:
      if (lookahead == 'r') ADVANCE(616);
      END_STATE();
    case 554:
      if (lookahead == 'r') ADVANCE(644);
      END_STATE();
    case 555:
      if (lookahead == 'r') ADVANCE(246);
      END_STATE();
    case 556:
      if (lookahead == 'r') ADVANCE(217);
      END_STATE();
    case 557:
      if (lookahead == 'r') ADVANCE(227);
      if (lookahead == 'v') ADVANCE(289);
      END_STATE();
    case 558:
      if (lookahead == 'r') ADVANCE(338);
      END_STATE();
    case 559:
      if (lookahead == 'r') ADVANCE(155);
      if (lookahead == 's') ADVANCE(515);
      if (lookahead == 'x') ADVANCE(588);
      END_STATE();
    case 560:
      if (lookahead == 'r') ADVANCE(188);
      END_STATE();
    case 561:
      if (lookahead == 'r') ADVANCE(342);
      END_STATE();
    case 562:
      if (lookahead == 'r') ADVANCE(255);
      END_STATE();
    case 563:
      if (lookahead == 'r') ADVANCE(690);
      END_STATE();
    case 564:
      if (lookahead == 'r') ADVANCE(360);
      END_STATE();
    case 565:
      if (lookahead == 's') ADVANCE(760);
      END_STATE();
    case 566:
      if (lookahead == 's') ADVANCE(729);
      END_STATE();
    case 567:
      if (lookahead == 's') ADVANCE(728);
      END_STATE();
    case 568:
      if (lookahead == 's') ADVANCE(740);
      END_STATE();
    case 569:
      if (lookahead == 's') ADVANCE(781);
      END_STATE();
    case 570:
      if (lookahead == 's') ADVANCE(813);
      END_STATE();
    case 571:
      if (lookahead == 's') ADVANCE(814);
      END_STATE();
    case 572:
      if (lookahead == 's') ADVANCE(816);
      END_STATE();
    case 573:
      if (lookahead == 's') ADVANCE(817);
      END_STATE();
    case 574:
      if (lookahead == 's') ADVANCE(818);
      END_STATE();
    case 575:
      if (lookahead == 's') ADVANCE(370);
      if (lookahead == 't') ADVANCE(100);
      END_STATE();
    case 576:
      if (lookahead == 's') ADVANCE(815);
      END_STATE();
    case 577:
      if (lookahead == 's') ADVANCE(60);
      END_STATE();
    case 578:
      if (lookahead == 's') ADVANCE(205);
      END_STATE();
    case 579:
      if (lookahead == 's') ADVANCE(161);
      END_STATE();
    case 580:
      if (lookahead == 's') ADVANCE(630);
      END_STATE();
    case 581:
      if (lookahead == 's') ADVANCE(64);
      END_STATE();
    case 582:
      if (lookahead == 's') ADVANCE(633);
      END_STATE();
    case 583:
      if (lookahead == 's') ADVANCE(319);
      END_STATE();
    case 584:
      if (lookahead == 's') ADVANCE(464);
      END_STATE();
    case 585:
      if (lookahead == 's') ADVANCE(76);
      END_STATE();
    case 586:
      if (lookahead == 's') ADVANCE(354);
      END_STATE();
    case 587:
      if (lookahead == 's') ADVANCE(343);
      END_STATE();
    case 588:
      if (lookahead == 's') ADVANCE(569);
      END_STATE();
    case 589:
      if (lookahead == 's') ADVANCE(611);
      END_STATE();
    case 590:
      if (lookahead == 's') ADVANCE(414);
      END_STATE();
    case 591:
      if (lookahead == 's') ADVANCE(650);
      END_STATE();
    case 592:
      if (lookahead == 's') ADVANCE(635);
      END_STATE();
    case 593:
      if (lookahead == 's') ADVANCE(266);
      END_STATE();
    case 594:
      if (lookahead == 's') ADVANCE(636);
      END_STATE();
    case 595:
      if (lookahead == 's') ADVANCE(640);
      END_STATE();
    case 596:
      if (lookahead == 's') ADVANCE(643);
      END_STATE();
    case 597:
      if (lookahead == 's') ADVANCE(248);
      END_STATE();
    case 598:
      if (lookahead == 's') ADVANCE(256);
      END_STATE();
    case 599:
      if (lookahead == 's') ADVANCE(654);
      END_STATE();
    case 600:
      if (lookahead == 's') ADVANCE(240);
      END_STATE();
    case 601:
      if (lookahead == 's') ADVANCE(598);
      END_STATE();
    case 602:
      if (lookahead == 's') ADVANCE(251);
      END_STATE();
    case 603:
      if (lookahead == 's') ADVANCE(79);
      END_STATE();
    case 604:
      if (lookahead == 's') ADVANCE(167);
      END_STATE();
    case 605:
      if (lookahead == 's') ADVANCE(656);
      END_STATE();
    case 606:
      if (lookahead == 's') ADVANCE(490);
      END_STATE();
    case 607:
      if (lookahead == 's') ADVANCE(491);
      END_STATE();
    case 608:
      if (lookahead == 't') ADVANCE(143);
      END_STATE();
    case 609:
      if (lookahead == 't') ADVANCE(765);
      END_STATE();
    case 610:
      if (lookahead == 't') ADVANCE(731);
      END_STATE();
    case 611:
      if (lookahead == 't') ADVANCE(786);
      END_STATE();
    case 612:
      if (lookahead == 't') ADVANCE(796);
      END_STATE();
    case 613:
      if (lookahead == 't') ADVANCE(823);
      END_STATE();
    case 614:
      if (lookahead == 't') ADVANCE(793);
      END_STATE();
    case 615:
      if (lookahead == 't') ADVANCE(801);
      END_STATE();
    case 616:
      if (lookahead == 't') ADVANCE(777);
      END_STATE();
    case 617:
      if (lookahead == 't') ADVANCE(821);
      END_STATE();
    case 618:
      if (lookahead == 't') ADVANCE(619);
      END_STATE();
    case 619:
      if (lookahead == 't') ADVANCE(497);
      END_STATE();
    case 620:
      if (lookahead == 't') ADVANCE(315);
      END_STATE();
    case 621:
      if (lookahead == 't') ADVANCE(694);
      END_STATE();
    case 622:
      if (lookahead == 't') ADVANCE(316);
      END_STATE();
    case 623:
      if (lookahead == 't') ADVANCE(101);
      END_STATE();
    case 624:
      if (lookahead == 't') ADVANCE(54);
      END_STATE();
    case 625:
      if (lookahead == 't') ADVANCE(322);
      END_STATE();
    case 626:
      if (lookahead == 't') ADVANCE(150);
      END_STATE();
    case 627:
      if (lookahead == 't') ADVANCE(323);
      END_STATE();
    case 628:
      if (lookahead == 't') ADVANCE(424);
      END_STATE();
    case 629:
      if (lookahead == 't') ADVANCE(317);
      END_STATE();
    case 630:
      if (lookahead == 't') ADVANCE(558);
      END_STATE();
    case 631:
      if (lookahead == 't') ADVANCE(24);
      END_STATE();
    case 632:
      if (lookahead == 't') ADVANCE(318);
      END_STATE();
    case 633:
      if (lookahead == 't') ADVANCE(418);
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
      if (lookahead == 't') ADVANCE(97);
      END_STATE();
    case 638:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 639:
      if (lookahead == 't') ADVANCE(68);
      END_STATE();
    case 640:
      if (lookahead == 't') ADVANCE(107);
      END_STATE();
    case 641:
      if (lookahead == 't') ADVANCE(537);
      END_STATE();
    case 642:
      if (lookahead == 't') ADVANCE(527);
      END_STATE();
    case 643:
      if (lookahead == 't') ADVANCE(21);
      END_STATE();
    case 644:
      if (lookahead == 't') ADVANCE(59);
      END_STATE();
    case 645:
      if (lookahead == 't') ADVANCE(238);
      END_STATE();
    case 646:
      if (lookahead == 't') ADVANCE(23);
      END_STATE();
    case 647:
      if (lookahead == 't') ADVANCE(247);
      END_STATE();
    case 648:
      if (lookahead == 't') ADVANCE(239);
      END_STATE();
    case 649:
      if (lookahead == 't') ADVANCE(249);
      END_STATE();
    case 650:
      if (lookahead == 't') ADVANCE(106);
      END_STATE();
    case 651:
      if (lookahead == 't') ADVANCE(84);
      END_STATE();
    case 652:
      if (lookahead == 't') ADVANCE(500);
      END_STATE();
    case 653:
      if (lookahead == 't') ADVANCE(350);
      END_STATE();
    case 654:
      if (lookahead == 't') ADVANCE(555);
      END_STATE();
    case 655:
      if (lookahead == 't') ADVANCE(652);
      END_STATE();
    case 656:
      if (lookahead == 't') ADVANCE(561);
      END_STATE();
    case 657:
      if (lookahead == 't') ADVANCE(358);
      END_STATE();
    case 658:
      if (lookahead == 't') ADVANCE(603);
      END_STATE();
    case 659:
      if (lookahead == 't') ADVANCE(513);
      END_STATE();
    case 660:
      if (lookahead == 't') ADVANCE(659);
      END_STATE();
    case 661:
      if (lookahead == 't') ADVANCE(89);
      END_STATE();
    case 662:
      if (lookahead == 'u') ADVANCE(204);
      END_STATE();
    case 663:
      if (lookahead == 'u') ADVANCE(139);
      END_STATE();
    case 664:
      if (lookahead == 'u') ADVANCE(501);
      END_STATE();
    case 665:
      if (lookahead == 'u') ADVANCE(385);
      END_STATE();
    case 666:
      if (lookahead == 'u') ADVANCE(512);
      END_STATE();
    case 667:
      if (lookahead == 'u') ADVANCE(378);
      END_STATE();
    case 668:
      if (lookahead == 'u') ADVANCE(282);
      END_STATE();
    case 669:
      if (lookahead == 'u') ADVANCE(422);
      END_STATE();
    case 670:
      if (lookahead == 'u') ADVANCE(442);
      END_STATE();
    case 671:
      if (lookahead == 'u') ADVANCE(544);
      END_STATE();
    case 672:
      if (lookahead == 'u') ADVANCE(543);
      END_STATE();
    case 673:
      if (lookahead == 'u') ADVANCE(627);
      END_STATE();
    case 674:
      if (lookahead == 'u') ADVANCE(547);
      END_STATE();
    case 675:
      if (lookahead == 'u') ADVANCE(259);
      END_STATE();
    case 676:
      if (lookahead == 'u') ADVANCE(268);
      END_STATE();
    case 677:
      if (lookahead == 'u') ADVANCE(269);
      END_STATE();
    case 678:
      if (lookahead == 'u') ADVANCE(284);
      END_STATE();
    case 679:
      if (lookahead == 'u') ADVANCE(130);
      END_STATE();
    case 680:
      if (lookahead == 'u') ADVANCE(287);
      END_STATE();
    case 681:
      if (lookahead == 'u') ADVANCE(383);
      END_STATE();
    case 682:
      if (lookahead == 'v') ADVANCE(49);
      END_STATE();
    case 683:
      if (lookahead == 'v') ADVANCE(235);
      END_STATE();
    case 684:
      if (lookahead == 'v') ADVANCE(340);
      END_STATE();
    case 685:
      if (lookahead == 'v') ADVANCE(454);
      END_STATE();
    case 686:
      if (lookahead == 'v') ADVANCE(274);
      END_STATE();
    case 687:
      if (lookahead == 'w') ADVANCE(22);
      END_STATE();
    case 688:
      if (lookahead == 'w') ADVANCE(339);
      END_STATE();
    case 689:
      if (lookahead == 'w') ADVANCE(129);
      END_STATE();
    case 690:
      if (lookahead == 'w') ADVANCE(117);
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
      if (lookahead == 'y') ADVANCE(387);
      END_STATE();
    case 699:
      if (lookahead == 'y') ADVANCE(645);
      END_STATE();
    case 700:
      if (lookahead == 'z') ADVANCE(476);
      END_STATE();
    case 701:
      if (lookahead == 'z') ADVANCE(257);
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
      if (lookahead == 'a') ADVANCE(399);
      if (lookahead == 'c') ADVANCE(294);
      if (lookahead == 'e') ADVANCE(410);
      if (lookahead == 'f') ADVANCE(91);
      if (lookahead == 'h') ADVANCE(618);
      if (lookahead == 'i') ADVANCE(495);
      if (lookahead == 'l') ADVANCE(262);
      if (lookahead == 'n') ADVANCE(453);
      if (lookahead == 'o') ADVANCE(517);
      if (lookahead == 'r') ADVANCE(93);
      if (lookahead == 's') ADVANCE(575);
      if (lookahead == 't') ADVANCE(445);
      if (lookahead == 'u') ADVANCE(493);
      if (lookahead == 'x') ADVANCE(449);
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
      if (lookahead == 'n') ADVANCE(735);
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
      ACCEPT_TOKEN(anon_sym_len);
      END_STATE();
    case 736:
      ACCEPT_TOKEN(anon_sym_ends_with);
      END_STATE();
    case 737:
      ACCEPT_TOKEN(anon_sym_lookup_json_string);
      END_STATE();
    case 738:
      ACCEPT_TOKEN(anon_sym_lower);
      END_STATE();
    case 739:
      ACCEPT_TOKEN(anon_sym_regex_replace);
      END_STATE();
    case 740:
      ACCEPT_TOKEN(anon_sym_remove_bytes);
      END_STATE();
    case 741:
      ACCEPT_TOKEN(anon_sym_starts_with);
      END_STATE();
    case 742:
      ACCEPT_TOKEN(anon_sym_to_string);
      END_STATE();
    case 743:
      ACCEPT_TOKEN(anon_sym_upper);
      END_STATE();
    case 744:
      ACCEPT_TOKEN(anon_sym_url_decode);
      END_STATE();
    case 745:
      ACCEPT_TOKEN(anon_sym_uuidv4);
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
      if (lookahead == '.') ADVANCE(98);
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
      if (lookahead == '.') ADVANCE(559);
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
      if (lookahead == '.') ADVANCE(160);
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
      if (lookahead == '.') ADVANCE(510);
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
      if (lookahead == '.') ADVANCE(511);
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
      if (lookahead == '.') ADVANCE(437);
      END_STATE();
    case 815:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(438);
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
  [42] = {.lex_state = 703},
  [43] = {.lex_state = 703},
  [44] = {.lex_state = 1},
  [45] = {.lex_state = 1},
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
  [67] = {.lex_state = 0},
  [68] = {.lex_state = 2},
  [69] = {.lex_state = 2},
  [70] = {.lex_state = 2},
  [71] = {.lex_state = 2},
  [72] = {.lex_state = 2},
  [73] = {.lex_state = 2},
  [74] = {.lex_state = 2},
  [75] = {.lex_state = 2},
  [76] = {.lex_state = 2},
  [77] = {.lex_state = 2},
  [78] = {.lex_state = 2},
  [79] = {.lex_state = 2},
  [80] = {.lex_state = 2},
  [81] = {.lex_state = 2},
  [82] = {.lex_state = 2},
  [83] = {.lex_state = 2},
  [84] = {.lex_state = 2},
  [85] = {.lex_state = 2},
  [86] = {.lex_state = 0},
  [87] = {.lex_state = 0},
  [88] = {.lex_state = 0},
  [89] = {.lex_state = 1},
  [90] = {.lex_state = 1},
  [91] = {.lex_state = 703},
  [92] = {.lex_state = 703},
  [93] = {.lex_state = 1},
  [94] = {.lex_state = 1},
  [95] = {.lex_state = 1},
  [96] = {.lex_state = 703},
  [97] = {.lex_state = 0},
  [98] = {.lex_state = 1},
  [99] = {.lex_state = 0},
  [100] = {.lex_state = 1},
  [101] = {.lex_state = 1},
  [102] = {.lex_state = 703},
  [103] = {.lex_state = 0},
  [104] = {.lex_state = 1},
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
  [122] = {.lex_state = 0},
  [123] = {.lex_state = 0},
  [124] = {.lex_state = 0},
  [125] = {.lex_state = 0},
  [126] = {.lex_state = 0},
  [127] = {.lex_state = 1},
  [128] = {.lex_state = 703},
  [129] = {.lex_state = 0},
  [130] = {.lex_state = 703},
  [131] = {.lex_state = 0},
  [132] = {.lex_state = 703},
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
  [144] = {.lex_state = 0},
  [145] = {.lex_state = 0},
  [146] = {.lex_state = 0},
  [147] = {.lex_state = 0},
  [148] = {.lex_state = 0},
  [149] = {.lex_state = 703},
  [150] = {.lex_state = 0},
  [151] = {.lex_state = 2},
  [152] = {.lex_state = 703},
  [153] = {.lex_state = 703},
  [154] = {.lex_state = 0},
  [155] = {.lex_state = 703},
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
  [177] = {.lex_state = 703},
  [178] = {.lex_state = 0},
  [179] = {.lex_state = 0},
  [180] = {.lex_state = 0},
  [181] = {.lex_state = 0},
  [182] = {.lex_state = 703},
  [183] = {.lex_state = 0},
  [184] = {.lex_state = 0},
  [185] = {.lex_state = 0},
  [186] = {.lex_state = 0},
  [187] = {.lex_state = 0},
  [188] = {.lex_state = 0},
  [189] = {.lex_state = 0},
  [190] = {.lex_state = 0},
  [191] = {.lex_state = 0},
  [192] = {.lex_state = 0},
  [193] = {.lex_state = 1},
  [194] = {.lex_state = 0},
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
    [anon_sym_len] = ACTIONS(1),
    [anon_sym_ends_with] = ACTIONS(1),
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
    [sym_source_file] = STATE(144),
    [sym__expression] = STATE(42),
    [sym_not_expression] = STATE(42),
    [sym_in_expression] = STATE(42),
    [sym_compound_expression] = STATE(42),
    [sym_simple_expression] = STATE(42),
    [sym__bool_lhs] = STATE(42),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(42),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(42),
    [sym_boolean] = STATE(42),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(42),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(5),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_len] = ACTIONS(11),
    [anon_sym_ends_with] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_true] = ACTIONS(33),
    [anon_sym_false] = ACTIONS(33),
    [anon_sym_not] = ACTIONS(35),
    [anon_sym_BANG] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(37),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(37),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(37),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(37),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(39),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(37),
    [anon_sym_ip_DOTsrc] = ACTIONS(41),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(43),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_http_DOTuser_agent] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(45),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(53),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(55),
    [anon_sym_ssl] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(55),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(55),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(55),
  },
  [2] = {
    [sym__expression] = STATE(42),
    [sym_not_expression] = STATE(42),
    [sym_in_expression] = STATE(42),
    [sym_compound_expression] = STATE(42),
    [sym_simple_expression] = STATE(42),
    [sym__bool_lhs] = STATE(42),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(42),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(42),
    [sym_boolean] = STATE(42),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(42),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(57),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(59),
    [anon_sym_LPAREN] = ACTIONS(62),
    [anon_sym_len] = ACTIONS(65),
    [anon_sym_ends_with] = ACTIONS(68),
    [anon_sym_lookup_json_string] = ACTIONS(71),
    [anon_sym_lower] = ACTIONS(74),
    [anon_sym_regex_replace] = ACTIONS(77),
    [anon_sym_remove_bytes] = ACTIONS(80),
    [anon_sym_starts_with] = ACTIONS(83),
    [anon_sym_to_string] = ACTIONS(86),
    [anon_sym_upper] = ACTIONS(89),
    [anon_sym_url_decode] = ACTIONS(92),
    [anon_sym_uuidv4] = ACTIONS(95),
    [anon_sym_true] = ACTIONS(98),
    [anon_sym_false] = ACTIONS(98),
    [anon_sym_not] = ACTIONS(101),
    [anon_sym_BANG] = ACTIONS(101),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(104),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(104),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(104),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(107),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(104),
    [anon_sym_ip_DOTsrc] = ACTIONS(110),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(113),
    [anon_sym_http_DOTcookie] = ACTIONS(116),
    [anon_sym_http_DOThost] = ACTIONS(116),
    [anon_sym_http_DOTreferer] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(119),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(119),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(116),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(116),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(116),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(122),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(125),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(128),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(128),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
  },
  [3] = {
    [sym__expression] = STATE(42),
    [sym_not_expression] = STATE(42),
    [sym_in_expression] = STATE(42),
    [sym_compound_expression] = STATE(42),
    [sym_simple_expression] = STATE(42),
    [sym__bool_lhs] = STATE(42),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(42),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(42),
    [sym_boolean] = STATE(42),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(42),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(134),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_len] = ACTIONS(11),
    [anon_sym_ends_with] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_true] = ACTIONS(33),
    [anon_sym_false] = ACTIONS(33),
    [anon_sym_not] = ACTIONS(35),
    [anon_sym_BANG] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(37),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(37),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(37),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(37),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(39),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(37),
    [anon_sym_ip_DOTsrc] = ACTIONS(41),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(43),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_http_DOTuser_agent] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(45),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(53),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(55),
    [anon_sym_ssl] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(55),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(55),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(55),
  },
  [4] = {
    [sym__expression] = STATE(17),
    [sym_not_expression] = STATE(17),
    [sym_in_expression] = STATE(17),
    [sym_compound_expression] = STATE(17),
    [sym_simple_expression] = STATE(17),
    [sym__bool_lhs] = STATE(17),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(17),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(17),
    [sym_boolean] = STATE(17),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(17),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_len] = ACTIONS(11),
    [anon_sym_ends_with] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_true] = ACTIONS(33),
    [anon_sym_false] = ACTIONS(33),
    [anon_sym_not] = ACTIONS(35),
    [anon_sym_BANG] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(37),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(37),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(37),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(37),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(39),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(37),
    [anon_sym_ip_DOTsrc] = ACTIONS(41),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(43),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_http_DOTuser_agent] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(45),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(53),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(55),
    [anon_sym_ssl] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(55),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(55),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(55),
  },
  [5] = {
    [sym__expression] = STATE(88),
    [sym_not_expression] = STATE(88),
    [sym_in_expression] = STATE(88),
    [sym_compound_expression] = STATE(88),
    [sym_simple_expression] = STATE(88),
    [sym__bool_lhs] = STATE(88),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(88),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(88),
    [sym_boolean] = STATE(88),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(88),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_len] = ACTIONS(11),
    [anon_sym_ends_with] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_true] = ACTIONS(33),
    [anon_sym_false] = ACTIONS(33),
    [anon_sym_not] = ACTIONS(35),
    [anon_sym_BANG] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(37),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(37),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(37),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(37),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(39),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(37),
    [anon_sym_ip_DOTsrc] = ACTIONS(41),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(43),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_http_DOTuser_agent] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(45),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(53),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(55),
    [anon_sym_ssl] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(55),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(55),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(55),
  },
  [6] = {
    [sym__expression] = STATE(21),
    [sym_not_expression] = STATE(21),
    [sym_in_expression] = STATE(21),
    [sym_compound_expression] = STATE(21),
    [sym_simple_expression] = STATE(21),
    [sym__bool_lhs] = STATE(21),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(21),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(21),
    [sym_boolean] = STATE(21),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(21),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_len] = ACTIONS(11),
    [anon_sym_ends_with] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_true] = ACTIONS(33),
    [anon_sym_false] = ACTIONS(33),
    [anon_sym_not] = ACTIONS(35),
    [anon_sym_BANG] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(37),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(37),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(37),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(37),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(39),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(37),
    [anon_sym_ip_DOTsrc] = ACTIONS(41),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(43),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_http_DOTuser_agent] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(45),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(53),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(55),
    [anon_sym_ssl] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(55),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(55),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(55),
  },
  [7] = {
    [sym__expression] = STATE(20),
    [sym_not_expression] = STATE(20),
    [sym_in_expression] = STATE(20),
    [sym_compound_expression] = STATE(20),
    [sym_simple_expression] = STATE(20),
    [sym__bool_lhs] = STATE(20),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(20),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(20),
    [sym_boolean] = STATE(20),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(20),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_len] = ACTIONS(11),
    [anon_sym_ends_with] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_true] = ACTIONS(33),
    [anon_sym_false] = ACTIONS(33),
    [anon_sym_not] = ACTIONS(35),
    [anon_sym_BANG] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(37),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(37),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(37),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(37),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(39),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(37),
    [anon_sym_ip_DOTsrc] = ACTIONS(41),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(43),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_http_DOTuser_agent] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(45),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(53),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(55),
    [anon_sym_ssl] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(55),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(55),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(55),
  },
  [8] = {
    [sym__expression] = STATE(18),
    [sym_not_expression] = STATE(18),
    [sym_in_expression] = STATE(18),
    [sym_compound_expression] = STATE(18),
    [sym_simple_expression] = STATE(18),
    [sym__bool_lhs] = STATE(18),
    [sym__number_lhs] = STATE(85),
    [sym__string_lhs] = STATE(81),
    [sym_string_func] = STATE(81),
    [sym_number_func] = STATE(85),
    [sym_bool_func] = STATE(18),
    [sym_ends_with_func] = STATE(30),
    [sym_lookup_func] = STATE(72),
    [sym_lower_func] = STATE(72),
    [sym_regex_replace_func] = STATE(72),
    [sym_remove_bytes_func] = STATE(72),
    [sym_starts_with_func] = STATE(30),
    [sym_to_string_func] = STATE(72),
    [sym_upper_func] = STATE(72),
    [sym_url_decode_func] = STATE(72),
    [sym_uuid_func] = STATE(72),
    [sym_group] = STATE(18),
    [sym_boolean] = STATE(18),
    [sym_not_operator] = STATE(4),
    [sym__array_lhs] = STATE(130),
    [sym__stringlike_field] = STATE(80),
    [sym_number_field] = STATE(85),
    [sym_ip_field] = STATE(90),
    [sym_string_field] = STATE(80),
    [sym_map_string_array_field] = STATE(128),
    [sym_array_string_field] = STATE(130),
    [sym_bool_field] = STATE(18),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_LPAREN] = ACTIONS(9),
    [anon_sym_len] = ACTIONS(11),
    [anon_sym_ends_with] = ACTIONS(13),
    [anon_sym_lookup_json_string] = ACTIONS(15),
    [anon_sym_lower] = ACTIONS(17),
    [anon_sym_regex_replace] = ACTIONS(19),
    [anon_sym_remove_bytes] = ACTIONS(21),
    [anon_sym_starts_with] = ACTIONS(23),
    [anon_sym_to_string] = ACTIONS(25),
    [anon_sym_upper] = ACTIONS(27),
    [anon_sym_url_decode] = ACTIONS(29),
    [anon_sym_uuidv4] = ACTIONS(31),
    [anon_sym_true] = ACTIONS(33),
    [anon_sym_false] = ACTIONS(33),
    [anon_sym_not] = ACTIONS(35),
    [anon_sym_BANG] = ACTIONS(35),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(37),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(37),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(37),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(37),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(39),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(37),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(37),
    [anon_sym_ip_DOTsrc] = ACTIONS(41),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(43),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_http_DOTuser_agent] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(45),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(45),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(51),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(53),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(55),
    [anon_sym_ssl] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(55),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(55),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(55),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(55),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(55),
  },
  [9] = {
    [ts_builtin_sym_end] = ACTIONS(136),
    [anon_sym_AMP_AMP] = ACTIONS(136),
    [anon_sym_and] = ACTIONS(136),
    [anon_sym_xor] = ACTIONS(136),
    [anon_sym_CARET_CARET] = ACTIONS(136),
    [anon_sym_or] = ACTIONS(136),
    [anon_sym_PIPE_PIPE] = ACTIONS(136),
    [anon_sym_RBRACE] = ACTIONS(136),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(136),
    [anon_sym_LPAREN] = ACTIONS(136),
    [anon_sym_RPAREN] = ACTIONS(136),
    [anon_sym_len] = ACTIONS(136),
    [anon_sym_ends_with] = ACTIONS(136),
    [anon_sym_lookup_json_string] = ACTIONS(136),
    [anon_sym_lower] = ACTIONS(136),
    [anon_sym_regex_replace] = ACTIONS(136),
    [anon_sym_remove_bytes] = ACTIONS(136),
    [anon_sym_starts_with] = ACTIONS(136),
    [anon_sym_to_string] = ACTIONS(136),
    [anon_sym_upper] = ACTIONS(136),
    [anon_sym_url_decode] = ACTIONS(136),
    [anon_sym_uuidv4] = ACTIONS(136),
    [anon_sym_true] = ACTIONS(136),
    [anon_sym_false] = ACTIONS(136),
    [sym_ipv4] = ACTIONS(136),
    [anon_sym_SLASH] = ACTIONS(138),
    [anon_sym_not] = ACTIONS(136),
    [anon_sym_BANG] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(136),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(136),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(136),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(136),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(136),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(140),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(136),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(136),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(136),
    [anon_sym_ip_DOTsrc] = ACTIONS(140),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(136),
    [anon_sym_http_DOTcookie] = ACTIONS(136),
    [anon_sym_http_DOThost] = ACTIONS(136),
    [anon_sym_http_DOTreferer] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(140),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(136),
    [anon_sym_http_DOTuser_agent] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(136),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(136),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(136),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(136),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(136),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(136),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(136),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(136),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(136),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(136),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(136),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(136),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(140),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(136),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(136),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(136),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(136),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(140),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(136),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(136),
    [anon_sym_ssl] = ACTIONS(136),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(136),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(136),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(136),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(136),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(136),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(136),
  },
  [10] = {
    [ts_builtin_sym_end] = ACTIONS(142),
    [anon_sym_AMP_AMP] = ACTIONS(142),
    [anon_sym_and] = ACTIONS(142),
    [anon_sym_xor] = ACTIONS(142),
    [anon_sym_CARET_CARET] = ACTIONS(142),
    [anon_sym_or] = ACTIONS(142),
    [anon_sym_PIPE_PIPE] = ACTIONS(142),
    [anon_sym_RBRACE] = ACTIONS(142),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(142),
    [anon_sym_LPAREN] = ACTIONS(142),
    [anon_sym_RPAREN] = ACTIONS(142),
    [anon_sym_len] = ACTIONS(142),
    [anon_sym_ends_with] = ACTIONS(142),
    [anon_sym_lookup_json_string] = ACTIONS(142),
    [anon_sym_lower] = ACTIONS(142),
    [anon_sym_regex_replace] = ACTIONS(142),
    [anon_sym_remove_bytes] = ACTIONS(142),
    [anon_sym_starts_with] = ACTIONS(142),
    [anon_sym_to_string] = ACTIONS(142),
    [anon_sym_upper] = ACTIONS(142),
    [anon_sym_url_decode] = ACTIONS(142),
    [anon_sym_uuidv4] = ACTIONS(142),
    [anon_sym_true] = ACTIONS(142),
    [anon_sym_false] = ACTIONS(142),
    [sym_ipv4] = ACTIONS(142),
    [anon_sym_not] = ACTIONS(142),
    [anon_sym_BANG] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(142),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(142),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(142),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(142),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(142),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(144),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(142),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(142),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(142),
    [anon_sym_ip_DOTsrc] = ACTIONS(144),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(142),
    [anon_sym_http_DOTcookie] = ACTIONS(142),
    [anon_sym_http_DOThost] = ACTIONS(142),
    [anon_sym_http_DOTreferer] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(142),
    [anon_sym_http_DOTuser_agent] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(142),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(142),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(142),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(142),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(142),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(142),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(142),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(142),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(142),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(142),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(142),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(142),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(144),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(142),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(142),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(142),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(142),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(144),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(142),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(142),
    [anon_sym_ssl] = ACTIONS(142),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(142),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(142),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(142),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(142),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(142),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(142),
  },
  [11] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(150),
    [anon_sym_AMP_AMP] = ACTIONS(150),
    [anon_sym_and] = ACTIONS(150),
    [anon_sym_xor] = ACTIONS(150),
    [anon_sym_CARET_CARET] = ACTIONS(150),
    [anon_sym_or] = ACTIONS(150),
    [anon_sym_PIPE_PIPE] = ACTIONS(150),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(150),
    [anon_sym_LPAREN] = ACTIONS(150),
    [anon_sym_RPAREN] = ACTIONS(150),
    [anon_sym_len] = ACTIONS(150),
    [anon_sym_ends_with] = ACTIONS(150),
    [anon_sym_lookup_json_string] = ACTIONS(150),
    [anon_sym_lower] = ACTIONS(150),
    [anon_sym_regex_replace] = ACTIONS(150),
    [anon_sym_remove_bytes] = ACTIONS(150),
    [anon_sym_starts_with] = ACTIONS(150),
    [anon_sym_to_string] = ACTIONS(150),
    [anon_sym_upper] = ACTIONS(150),
    [anon_sym_url_decode] = ACTIONS(150),
    [anon_sym_uuidv4] = ACTIONS(150),
    [anon_sym_true] = ACTIONS(150),
    [anon_sym_false] = ACTIONS(150),
    [anon_sym_not] = ACTIONS(150),
    [anon_sym_BANG] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(150),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(150),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(150),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(150),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(150),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(152),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(150),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(150),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(150),
    [anon_sym_ip_DOTsrc] = ACTIONS(152),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(150),
    [anon_sym_http_DOTcookie] = ACTIONS(150),
    [anon_sym_http_DOThost] = ACTIONS(150),
    [anon_sym_http_DOTreferer] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(150),
    [anon_sym_http_DOTuser_agent] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(150),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(150),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(150),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(150),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(150),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(150),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(150),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(150),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(150),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(150),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(150),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(150),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(152),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(150),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(150),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(150),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(150),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(152),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(150),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(150),
    [anon_sym_ssl] = ACTIONS(150),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(150),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(150),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(150),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(150),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(150),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(150),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(154),
    [anon_sym_AMP_AMP] = ACTIONS(154),
    [anon_sym_and] = ACTIONS(154),
    [anon_sym_xor] = ACTIONS(154),
    [anon_sym_CARET_CARET] = ACTIONS(154),
    [anon_sym_or] = ACTIONS(154),
    [anon_sym_PIPE_PIPE] = ACTIONS(154),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(154),
    [anon_sym_LPAREN] = ACTIONS(154),
    [anon_sym_RPAREN] = ACTIONS(154),
    [anon_sym_len] = ACTIONS(154),
    [anon_sym_ends_with] = ACTIONS(154),
    [anon_sym_lookup_json_string] = ACTIONS(154),
    [anon_sym_lower] = ACTIONS(154),
    [anon_sym_regex_replace] = ACTIONS(154),
    [anon_sym_remove_bytes] = ACTIONS(154),
    [anon_sym_starts_with] = ACTIONS(154),
    [anon_sym_to_string] = ACTIONS(154),
    [anon_sym_upper] = ACTIONS(154),
    [anon_sym_url_decode] = ACTIONS(154),
    [anon_sym_uuidv4] = ACTIONS(154),
    [anon_sym_true] = ACTIONS(154),
    [anon_sym_false] = ACTIONS(154),
    [anon_sym_not] = ACTIONS(154),
    [anon_sym_BANG] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(154),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(154),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(154),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(154),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(154),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(156),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(154),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(154),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(154),
    [anon_sym_ip_DOTsrc] = ACTIONS(156),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(154),
    [anon_sym_http_DOTcookie] = ACTIONS(154),
    [anon_sym_http_DOThost] = ACTIONS(154),
    [anon_sym_http_DOTreferer] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(154),
    [anon_sym_http_DOTuser_agent] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(154),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(154),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(154),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(154),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(154),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(154),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(154),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(154),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(154),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(154),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(154),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(154),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(156),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(154),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(154),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(154),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(154),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(156),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(154),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(154),
    [anon_sym_ssl] = ACTIONS(154),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(154),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(154),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(154),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(154),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(154),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(154),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(158),
    [anon_sym_AMP_AMP] = ACTIONS(158),
    [anon_sym_and] = ACTIONS(158),
    [anon_sym_xor] = ACTIONS(158),
    [anon_sym_CARET_CARET] = ACTIONS(158),
    [anon_sym_or] = ACTIONS(158),
    [anon_sym_PIPE_PIPE] = ACTIONS(158),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(158),
    [anon_sym_LPAREN] = ACTIONS(158),
    [anon_sym_RPAREN] = ACTIONS(158),
    [anon_sym_len] = ACTIONS(158),
    [anon_sym_ends_with] = ACTIONS(158),
    [anon_sym_lookup_json_string] = ACTIONS(158),
    [anon_sym_lower] = ACTIONS(158),
    [anon_sym_regex_replace] = ACTIONS(158),
    [anon_sym_remove_bytes] = ACTIONS(158),
    [anon_sym_starts_with] = ACTIONS(158),
    [anon_sym_to_string] = ACTIONS(158),
    [anon_sym_upper] = ACTIONS(158),
    [anon_sym_url_decode] = ACTIONS(158),
    [anon_sym_uuidv4] = ACTIONS(158),
    [anon_sym_true] = ACTIONS(158),
    [anon_sym_false] = ACTIONS(158),
    [anon_sym_not] = ACTIONS(158),
    [anon_sym_BANG] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(158),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(158),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(158),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(158),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(158),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(160),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(158),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(158),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(158),
    [anon_sym_ip_DOTsrc] = ACTIONS(160),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(158),
    [anon_sym_http_DOTcookie] = ACTIONS(158),
    [anon_sym_http_DOThost] = ACTIONS(158),
    [anon_sym_http_DOTreferer] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(158),
    [anon_sym_http_DOTuser_agent] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(158),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(158),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(158),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(158),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(158),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(158),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(158),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(158),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(158),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(158),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(158),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(158),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(160),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(158),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(158),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(158),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(158),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(160),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(158),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(158),
    [anon_sym_ssl] = ACTIONS(158),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(158),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(158),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(158),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(158),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(158),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(158),
  },
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(162),
    [anon_sym_AMP_AMP] = ACTIONS(162),
    [anon_sym_and] = ACTIONS(162),
    [anon_sym_xor] = ACTIONS(162),
    [anon_sym_CARET_CARET] = ACTIONS(162),
    [anon_sym_or] = ACTIONS(162),
    [anon_sym_PIPE_PIPE] = ACTIONS(162),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(162),
    [anon_sym_LPAREN] = ACTIONS(162),
    [anon_sym_RPAREN] = ACTIONS(162),
    [anon_sym_len] = ACTIONS(162),
    [anon_sym_ends_with] = ACTIONS(162),
    [anon_sym_lookup_json_string] = ACTIONS(162),
    [anon_sym_lower] = ACTIONS(162),
    [anon_sym_regex_replace] = ACTIONS(162),
    [anon_sym_remove_bytes] = ACTIONS(162),
    [anon_sym_starts_with] = ACTIONS(162),
    [anon_sym_to_string] = ACTIONS(162),
    [anon_sym_upper] = ACTIONS(162),
    [anon_sym_url_decode] = ACTIONS(162),
    [anon_sym_uuidv4] = ACTIONS(162),
    [anon_sym_true] = ACTIONS(162),
    [anon_sym_false] = ACTIONS(162),
    [anon_sym_not] = ACTIONS(162),
    [anon_sym_BANG] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(162),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(162),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(162),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(162),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(162),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(164),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(162),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(162),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(162),
    [anon_sym_ip_DOTsrc] = ACTIONS(164),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(162),
    [anon_sym_http_DOTcookie] = ACTIONS(162),
    [anon_sym_http_DOThost] = ACTIONS(162),
    [anon_sym_http_DOTreferer] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(162),
    [anon_sym_http_DOTuser_agent] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(162),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(162),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(162),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(162),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(162),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(162),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(162),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(162),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(162),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(162),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(162),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(162),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(164),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(162),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(162),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(162),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(162),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(164),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(162),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(162),
    [anon_sym_ssl] = ACTIONS(162),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(162),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(162),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(162),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(162),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(162),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(162),
  },
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(166),
    [anon_sym_AMP_AMP] = ACTIONS(166),
    [anon_sym_and] = ACTIONS(166),
    [anon_sym_xor] = ACTIONS(166),
    [anon_sym_CARET_CARET] = ACTIONS(166),
    [anon_sym_or] = ACTIONS(166),
    [anon_sym_PIPE_PIPE] = ACTIONS(166),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(166),
    [anon_sym_LPAREN] = ACTIONS(166),
    [anon_sym_RPAREN] = ACTIONS(166),
    [anon_sym_len] = ACTIONS(166),
    [anon_sym_ends_with] = ACTIONS(166),
    [anon_sym_lookup_json_string] = ACTIONS(166),
    [anon_sym_lower] = ACTIONS(166),
    [anon_sym_regex_replace] = ACTIONS(166),
    [anon_sym_remove_bytes] = ACTIONS(166),
    [anon_sym_starts_with] = ACTIONS(166),
    [anon_sym_to_string] = ACTIONS(166),
    [anon_sym_upper] = ACTIONS(166),
    [anon_sym_url_decode] = ACTIONS(166),
    [anon_sym_uuidv4] = ACTIONS(166),
    [anon_sym_true] = ACTIONS(166),
    [anon_sym_false] = ACTIONS(166),
    [anon_sym_not] = ACTIONS(166),
    [anon_sym_BANG] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(166),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(166),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(166),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(166),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(166),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(168),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(166),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(166),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(166),
    [anon_sym_ip_DOTsrc] = ACTIONS(168),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(166),
    [anon_sym_http_DOTcookie] = ACTIONS(166),
    [anon_sym_http_DOThost] = ACTIONS(166),
    [anon_sym_http_DOTreferer] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(166),
    [anon_sym_http_DOTuser_agent] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(166),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(166),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(166),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(166),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(166),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(166),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(166),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(166),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(166),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(166),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(166),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(166),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(168),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(166),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(166),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(166),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(166),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(168),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(166),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(166),
    [anon_sym_ssl] = ACTIONS(166),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(166),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(166),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(166),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(166),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(166),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(166),
  },
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(170),
    [anon_sym_AMP_AMP] = ACTIONS(170),
    [anon_sym_and] = ACTIONS(170),
    [anon_sym_xor] = ACTIONS(170),
    [anon_sym_CARET_CARET] = ACTIONS(170),
    [anon_sym_or] = ACTIONS(170),
    [anon_sym_PIPE_PIPE] = ACTIONS(170),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(170),
    [anon_sym_LPAREN] = ACTIONS(170),
    [anon_sym_RPAREN] = ACTIONS(170),
    [anon_sym_len] = ACTIONS(170),
    [anon_sym_ends_with] = ACTIONS(170),
    [anon_sym_lookup_json_string] = ACTIONS(170),
    [anon_sym_lower] = ACTIONS(170),
    [anon_sym_regex_replace] = ACTIONS(170),
    [anon_sym_remove_bytes] = ACTIONS(170),
    [anon_sym_starts_with] = ACTIONS(170),
    [anon_sym_to_string] = ACTIONS(170),
    [anon_sym_upper] = ACTIONS(170),
    [anon_sym_url_decode] = ACTIONS(170),
    [anon_sym_uuidv4] = ACTIONS(170),
    [anon_sym_true] = ACTIONS(170),
    [anon_sym_false] = ACTIONS(170),
    [anon_sym_not] = ACTIONS(170),
    [anon_sym_BANG] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(170),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(170),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(172),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(170),
    [anon_sym_ip_DOTsrc] = ACTIONS(172),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(170),
    [anon_sym_http_DOTcookie] = ACTIONS(170),
    [anon_sym_http_DOThost] = ACTIONS(170),
    [anon_sym_http_DOTreferer] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(172),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(170),
    [anon_sym_http_DOTuser_agent] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(170),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(172),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(170),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(170),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(172),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(170),
    [anon_sym_ssl] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(170),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(170),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(170),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(170),
  },
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(174),
    [anon_sym_AMP_AMP] = ACTIONS(174),
    [anon_sym_and] = ACTIONS(174),
    [anon_sym_xor] = ACTIONS(174),
    [anon_sym_CARET_CARET] = ACTIONS(174),
    [anon_sym_or] = ACTIONS(174),
    [anon_sym_PIPE_PIPE] = ACTIONS(174),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(174),
    [anon_sym_LPAREN] = ACTIONS(174),
    [anon_sym_RPAREN] = ACTIONS(174),
    [anon_sym_len] = ACTIONS(174),
    [anon_sym_ends_with] = ACTIONS(174),
    [anon_sym_lookup_json_string] = ACTIONS(174),
    [anon_sym_lower] = ACTIONS(174),
    [anon_sym_regex_replace] = ACTIONS(174),
    [anon_sym_remove_bytes] = ACTIONS(174),
    [anon_sym_starts_with] = ACTIONS(174),
    [anon_sym_to_string] = ACTIONS(174),
    [anon_sym_upper] = ACTIONS(174),
    [anon_sym_url_decode] = ACTIONS(174),
    [anon_sym_uuidv4] = ACTIONS(174),
    [anon_sym_true] = ACTIONS(174),
    [anon_sym_false] = ACTIONS(174),
    [anon_sym_not] = ACTIONS(174),
    [anon_sym_BANG] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(174),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(174),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(174),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(174),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(174),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(176),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(174),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(174),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(174),
    [anon_sym_ip_DOTsrc] = ACTIONS(176),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(174),
    [anon_sym_http_DOTcookie] = ACTIONS(174),
    [anon_sym_http_DOThost] = ACTIONS(174),
    [anon_sym_http_DOTreferer] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(174),
    [anon_sym_http_DOTuser_agent] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(174),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(174),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(174),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(174),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(174),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(174),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(174),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(174),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(174),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(174),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(174),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(174),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(176),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(174),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(174),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(174),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(174),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(176),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(174),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(174),
    [anon_sym_ssl] = ACTIONS(174),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(174),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(174),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(174),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(174),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(174),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(174),
  },
  [20] = {
    [ts_builtin_sym_end] = ACTIONS(170),
    [anon_sym_AMP_AMP] = ACTIONS(178),
    [anon_sym_and] = ACTIONS(178),
    [anon_sym_xor] = ACTIONS(170),
    [anon_sym_CARET_CARET] = ACTIONS(170),
    [anon_sym_or] = ACTIONS(170),
    [anon_sym_PIPE_PIPE] = ACTIONS(170),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(170),
    [anon_sym_LPAREN] = ACTIONS(170),
    [anon_sym_RPAREN] = ACTIONS(170),
    [anon_sym_len] = ACTIONS(170),
    [anon_sym_ends_with] = ACTIONS(170),
    [anon_sym_lookup_json_string] = ACTIONS(170),
    [anon_sym_lower] = ACTIONS(170),
    [anon_sym_regex_replace] = ACTIONS(170),
    [anon_sym_remove_bytes] = ACTIONS(170),
    [anon_sym_starts_with] = ACTIONS(170),
    [anon_sym_to_string] = ACTIONS(170),
    [anon_sym_upper] = ACTIONS(170),
    [anon_sym_url_decode] = ACTIONS(170),
    [anon_sym_uuidv4] = ACTIONS(170),
    [anon_sym_true] = ACTIONS(170),
    [anon_sym_false] = ACTIONS(170),
    [anon_sym_not] = ACTIONS(170),
    [anon_sym_BANG] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(170),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(170),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(172),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(170),
    [anon_sym_ip_DOTsrc] = ACTIONS(172),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(170),
    [anon_sym_http_DOTcookie] = ACTIONS(170),
    [anon_sym_http_DOThost] = ACTIONS(170),
    [anon_sym_http_DOTreferer] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(172),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(170),
    [anon_sym_http_DOTuser_agent] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(170),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(172),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(170),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(170),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(172),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(170),
    [anon_sym_ssl] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(170),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(170),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(170),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(170),
  },
  [21] = {
    [ts_builtin_sym_end] = ACTIONS(170),
    [anon_sym_AMP_AMP] = ACTIONS(178),
    [anon_sym_and] = ACTIONS(178),
    [anon_sym_xor] = ACTIONS(180),
    [anon_sym_CARET_CARET] = ACTIONS(180),
    [anon_sym_or] = ACTIONS(170),
    [anon_sym_PIPE_PIPE] = ACTIONS(170),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(170),
    [anon_sym_LPAREN] = ACTIONS(170),
    [anon_sym_RPAREN] = ACTIONS(170),
    [anon_sym_len] = ACTIONS(170),
    [anon_sym_ends_with] = ACTIONS(170),
    [anon_sym_lookup_json_string] = ACTIONS(170),
    [anon_sym_lower] = ACTIONS(170),
    [anon_sym_regex_replace] = ACTIONS(170),
    [anon_sym_remove_bytes] = ACTIONS(170),
    [anon_sym_starts_with] = ACTIONS(170),
    [anon_sym_to_string] = ACTIONS(170),
    [anon_sym_upper] = ACTIONS(170),
    [anon_sym_url_decode] = ACTIONS(170),
    [anon_sym_uuidv4] = ACTIONS(170),
    [anon_sym_true] = ACTIONS(170),
    [anon_sym_false] = ACTIONS(170),
    [anon_sym_not] = ACTIONS(170),
    [anon_sym_BANG] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(170),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(170),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(172),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(170),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(170),
    [anon_sym_ip_DOTsrc] = ACTIONS(172),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(170),
    [anon_sym_http_DOTcookie] = ACTIONS(170),
    [anon_sym_http_DOThost] = ACTIONS(170),
    [anon_sym_http_DOTreferer] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(172),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(170),
    [anon_sym_http_DOTuser_agent] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(170),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(170),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(172),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(170),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(170),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(170),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(172),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(170),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(170),
    [anon_sym_ssl] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(170),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(170),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(170),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(170),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(170),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(170),
  },
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(182),
    [anon_sym_AMP_AMP] = ACTIONS(182),
    [anon_sym_and] = ACTIONS(182),
    [anon_sym_xor] = ACTIONS(182),
    [anon_sym_CARET_CARET] = ACTIONS(182),
    [anon_sym_or] = ACTIONS(182),
    [anon_sym_PIPE_PIPE] = ACTIONS(182),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(182),
    [anon_sym_LPAREN] = ACTIONS(182),
    [anon_sym_RPAREN] = ACTIONS(182),
    [anon_sym_len] = ACTIONS(182),
    [anon_sym_ends_with] = ACTIONS(182),
    [anon_sym_lookup_json_string] = ACTIONS(182),
    [anon_sym_lower] = ACTIONS(182),
    [anon_sym_regex_replace] = ACTIONS(182),
    [anon_sym_remove_bytes] = ACTIONS(182),
    [anon_sym_starts_with] = ACTIONS(182),
    [anon_sym_to_string] = ACTIONS(182),
    [anon_sym_upper] = ACTIONS(182),
    [anon_sym_url_decode] = ACTIONS(182),
    [anon_sym_uuidv4] = ACTIONS(182),
    [anon_sym_true] = ACTIONS(182),
    [anon_sym_false] = ACTIONS(182),
    [anon_sym_not] = ACTIONS(182),
    [anon_sym_BANG] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(182),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(182),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(182),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(182),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(182),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(184),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(182),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(182),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(182),
    [anon_sym_ip_DOTsrc] = ACTIONS(184),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(182),
    [anon_sym_http_DOTcookie] = ACTIONS(182),
    [anon_sym_http_DOThost] = ACTIONS(182),
    [anon_sym_http_DOTreferer] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(182),
    [anon_sym_http_DOTuser_agent] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(182),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(182),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(182),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(182),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(182),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(182),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(182),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(182),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(182),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(182),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(182),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(182),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(184),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(182),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(182),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(182),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(182),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(184),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(182),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(182),
    [anon_sym_ssl] = ACTIONS(182),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(182),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(182),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(182),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(182),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(182),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(182),
  },
  [23] = {
    [ts_builtin_sym_end] = ACTIONS(186),
    [anon_sym_AMP_AMP] = ACTIONS(186),
    [anon_sym_and] = ACTIONS(186),
    [anon_sym_xor] = ACTIONS(186),
    [anon_sym_CARET_CARET] = ACTIONS(186),
    [anon_sym_or] = ACTIONS(186),
    [anon_sym_PIPE_PIPE] = ACTIONS(186),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(186),
    [anon_sym_LPAREN] = ACTIONS(186),
    [anon_sym_RPAREN] = ACTIONS(186),
    [anon_sym_len] = ACTIONS(186),
    [anon_sym_ends_with] = ACTIONS(186),
    [anon_sym_lookup_json_string] = ACTIONS(186),
    [anon_sym_lower] = ACTIONS(186),
    [anon_sym_regex_replace] = ACTIONS(186),
    [anon_sym_remove_bytes] = ACTIONS(186),
    [anon_sym_starts_with] = ACTIONS(186),
    [anon_sym_to_string] = ACTIONS(186),
    [anon_sym_upper] = ACTIONS(186),
    [anon_sym_url_decode] = ACTIONS(186),
    [anon_sym_uuidv4] = ACTIONS(186),
    [anon_sym_true] = ACTIONS(186),
    [anon_sym_false] = ACTIONS(186),
    [anon_sym_not] = ACTIONS(186),
    [anon_sym_BANG] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(186),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(186),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(186),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(186),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(186),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(188),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(186),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(186),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(186),
    [anon_sym_ip_DOTsrc] = ACTIONS(188),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(186),
    [anon_sym_http_DOTcookie] = ACTIONS(186),
    [anon_sym_http_DOThost] = ACTIONS(186),
    [anon_sym_http_DOTreferer] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(186),
    [anon_sym_http_DOTuser_agent] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(186),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(186),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(186),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(186),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(186),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(186),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(186),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(186),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(186),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(186),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(186),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(186),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(188),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(186),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(186),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(186),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(186),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(188),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(186),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(186),
    [anon_sym_ssl] = ACTIONS(186),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(186),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(186),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(186),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(186),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(186),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(186),
  },
  [24] = {
    [ts_builtin_sym_end] = ACTIONS(190),
    [anon_sym_AMP_AMP] = ACTIONS(190),
    [anon_sym_and] = ACTIONS(190),
    [anon_sym_xor] = ACTIONS(190),
    [anon_sym_CARET_CARET] = ACTIONS(190),
    [anon_sym_or] = ACTIONS(190),
    [anon_sym_PIPE_PIPE] = ACTIONS(190),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(190),
    [anon_sym_LPAREN] = ACTIONS(190),
    [anon_sym_RPAREN] = ACTIONS(190),
    [anon_sym_len] = ACTIONS(190),
    [anon_sym_ends_with] = ACTIONS(190),
    [anon_sym_lookup_json_string] = ACTIONS(190),
    [anon_sym_lower] = ACTIONS(190),
    [anon_sym_regex_replace] = ACTIONS(190),
    [anon_sym_remove_bytes] = ACTIONS(190),
    [anon_sym_starts_with] = ACTIONS(190),
    [anon_sym_to_string] = ACTIONS(190),
    [anon_sym_upper] = ACTIONS(190),
    [anon_sym_url_decode] = ACTIONS(190),
    [anon_sym_uuidv4] = ACTIONS(190),
    [anon_sym_true] = ACTIONS(190),
    [anon_sym_false] = ACTIONS(190),
    [anon_sym_not] = ACTIONS(190),
    [anon_sym_BANG] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(190),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(190),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(190),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(190),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(190),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(192),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(190),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(190),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(190),
    [anon_sym_ip_DOTsrc] = ACTIONS(192),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(190),
    [anon_sym_http_DOTcookie] = ACTIONS(190),
    [anon_sym_http_DOThost] = ACTIONS(190),
    [anon_sym_http_DOTreferer] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(192),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(190),
    [anon_sym_http_DOTuser_agent] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(190),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(190),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(190),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(190),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(190),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(190),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(190),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(190),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(190),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(190),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(190),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(190),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(192),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(190),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(190),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(190),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(190),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(192),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(190),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(190),
    [anon_sym_ssl] = ACTIONS(190),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(190),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(190),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(190),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(190),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(190),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(190),
  },
  [25] = {
    [ts_builtin_sym_end] = ACTIONS(194),
    [anon_sym_AMP_AMP] = ACTIONS(194),
    [anon_sym_and] = ACTIONS(194),
    [anon_sym_xor] = ACTIONS(194),
    [anon_sym_CARET_CARET] = ACTIONS(194),
    [anon_sym_or] = ACTIONS(194),
    [anon_sym_PIPE_PIPE] = ACTIONS(194),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(194),
    [anon_sym_LPAREN] = ACTIONS(194),
    [anon_sym_RPAREN] = ACTIONS(194),
    [anon_sym_len] = ACTIONS(194),
    [anon_sym_ends_with] = ACTIONS(194),
    [anon_sym_lookup_json_string] = ACTIONS(194),
    [anon_sym_lower] = ACTIONS(194),
    [anon_sym_regex_replace] = ACTIONS(194),
    [anon_sym_remove_bytes] = ACTIONS(194),
    [anon_sym_starts_with] = ACTIONS(194),
    [anon_sym_to_string] = ACTIONS(194),
    [anon_sym_upper] = ACTIONS(194),
    [anon_sym_url_decode] = ACTIONS(194),
    [anon_sym_uuidv4] = ACTIONS(194),
    [anon_sym_true] = ACTIONS(194),
    [anon_sym_false] = ACTIONS(194),
    [anon_sym_not] = ACTIONS(194),
    [anon_sym_BANG] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(194),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(194),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(194),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(194),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(194),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(196),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(194),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(194),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(194),
    [anon_sym_ip_DOTsrc] = ACTIONS(196),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(194),
    [anon_sym_http_DOTcookie] = ACTIONS(194),
    [anon_sym_http_DOThost] = ACTIONS(194),
    [anon_sym_http_DOTreferer] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(196),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(194),
    [anon_sym_http_DOTuser_agent] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(194),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(194),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(194),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(194),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(194),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(194),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(194),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(194),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(194),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(194),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(194),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(194),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(196),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(194),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(194),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(194),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(194),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(196),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(194),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(194),
    [anon_sym_ssl] = ACTIONS(194),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(194),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(194),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(194),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(194),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(194),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(194),
  },
  [26] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [28] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [29] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [30] = {
    [ts_builtin_sym_end] = ACTIONS(198),
    [anon_sym_AMP_AMP] = ACTIONS(198),
    [anon_sym_and] = ACTIONS(198),
    [anon_sym_xor] = ACTIONS(198),
    [anon_sym_CARET_CARET] = ACTIONS(198),
    [anon_sym_or] = ACTIONS(198),
    [anon_sym_PIPE_PIPE] = ACTIONS(198),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(198),
    [anon_sym_LPAREN] = ACTIONS(198),
    [anon_sym_RPAREN] = ACTIONS(198),
    [anon_sym_len] = ACTIONS(198),
    [anon_sym_ends_with] = ACTIONS(198),
    [anon_sym_lookup_json_string] = ACTIONS(198),
    [anon_sym_lower] = ACTIONS(198),
    [anon_sym_regex_replace] = ACTIONS(198),
    [anon_sym_remove_bytes] = ACTIONS(198),
    [anon_sym_starts_with] = ACTIONS(198),
    [anon_sym_to_string] = ACTIONS(198),
    [anon_sym_upper] = ACTIONS(198),
    [anon_sym_url_decode] = ACTIONS(198),
    [anon_sym_uuidv4] = ACTIONS(198),
    [anon_sym_true] = ACTIONS(198),
    [anon_sym_false] = ACTIONS(198),
    [anon_sym_not] = ACTIONS(198),
    [anon_sym_BANG] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(198),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(198),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(198),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(198),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(198),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(200),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(198),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(198),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(198),
    [anon_sym_ip_DOTsrc] = ACTIONS(200),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(198),
    [anon_sym_http_DOTcookie] = ACTIONS(198),
    [anon_sym_http_DOThost] = ACTIONS(198),
    [anon_sym_http_DOTreferer] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(200),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(198),
    [anon_sym_http_DOTuser_agent] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(198),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(198),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(198),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(198),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(198),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(198),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(198),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(198),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(198),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(198),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(198),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(198),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(200),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(198),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(198),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(198),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(198),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(200),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(198),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(198),
    [anon_sym_ssl] = ACTIONS(198),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(198),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(198),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(198),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(198),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(198),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(198),
  },
  [31] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [32] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [33] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [34] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [35] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [36] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [37] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [38] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [39] = {
    [ts_builtin_sym_end] = ACTIONS(146),
    [anon_sym_AMP_AMP] = ACTIONS(146),
    [anon_sym_and] = ACTIONS(146),
    [anon_sym_xor] = ACTIONS(146),
    [anon_sym_CARET_CARET] = ACTIONS(146),
    [anon_sym_or] = ACTIONS(146),
    [anon_sym_PIPE_PIPE] = ACTIONS(146),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(146),
    [anon_sym_LPAREN] = ACTIONS(146),
    [anon_sym_RPAREN] = ACTIONS(146),
    [anon_sym_len] = ACTIONS(146),
    [anon_sym_ends_with] = ACTIONS(146),
    [anon_sym_lookup_json_string] = ACTIONS(146),
    [anon_sym_lower] = ACTIONS(146),
    [anon_sym_regex_replace] = ACTIONS(146),
    [anon_sym_remove_bytes] = ACTIONS(146),
    [anon_sym_starts_with] = ACTIONS(146),
    [anon_sym_to_string] = ACTIONS(146),
    [anon_sym_upper] = ACTIONS(146),
    [anon_sym_url_decode] = ACTIONS(146),
    [anon_sym_uuidv4] = ACTIONS(146),
    [anon_sym_true] = ACTIONS(146),
    [anon_sym_false] = ACTIONS(146),
    [anon_sym_not] = ACTIONS(146),
    [anon_sym_BANG] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(146),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(146),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(148),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(146),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(146),
    [anon_sym_ip_DOTsrc] = ACTIONS(148),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(146),
    [anon_sym_http_DOTcookie] = ACTIONS(146),
    [anon_sym_http_DOThost] = ACTIONS(146),
    [anon_sym_http_DOTreferer] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_http_DOTuser_agent] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(146),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(146),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(148),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(146),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(146),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(146),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(148),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(146),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(146),
    [anon_sym_ssl] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(146),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(146),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(146),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(146),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(146),
  },
  [40] = {
    [ts_builtin_sym_end] = ACTIONS(202),
    [anon_sym_AMP_AMP] = ACTIONS(202),
    [anon_sym_and] = ACTIONS(202),
    [anon_sym_xor] = ACTIONS(202),
    [anon_sym_CARET_CARET] = ACTIONS(202),
    [anon_sym_or] = ACTIONS(202),
    [anon_sym_PIPE_PIPE] = ACTIONS(202),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(202),
    [anon_sym_LPAREN] = ACTIONS(202),
    [anon_sym_RPAREN] = ACTIONS(202),
    [anon_sym_len] = ACTIONS(202),
    [anon_sym_ends_with] = ACTIONS(202),
    [anon_sym_lookup_json_string] = ACTIONS(202),
    [anon_sym_lower] = ACTIONS(202),
    [anon_sym_regex_replace] = ACTIONS(202),
    [anon_sym_remove_bytes] = ACTIONS(202),
    [anon_sym_starts_with] = ACTIONS(202),
    [anon_sym_to_string] = ACTIONS(202),
    [anon_sym_upper] = ACTIONS(202),
    [anon_sym_url_decode] = ACTIONS(202),
    [anon_sym_uuidv4] = ACTIONS(202),
    [anon_sym_true] = ACTIONS(202),
    [anon_sym_false] = ACTIONS(202),
    [anon_sym_not] = ACTIONS(202),
    [anon_sym_BANG] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(202),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(202),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(202),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(202),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(202),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(204),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(202),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(202),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(202),
    [anon_sym_ip_DOTsrc] = ACTIONS(204),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(202),
    [anon_sym_http_DOTcookie] = ACTIONS(202),
    [anon_sym_http_DOThost] = ACTIONS(202),
    [anon_sym_http_DOTreferer] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(204),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(202),
    [anon_sym_http_DOTuser_agent] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(202),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(202),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(202),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(202),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(202),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(202),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(202),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(202),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(202),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(202),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(202),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(202),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(204),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(202),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(202),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(202),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(202),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(204),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(202),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(202),
    [anon_sym_ssl] = ACTIONS(202),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(202),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(202),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(202),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(202),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(202),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(202),
  },
  [41] = {
    [ts_builtin_sym_end] = ACTIONS(206),
    [anon_sym_AMP_AMP] = ACTIONS(206),
    [anon_sym_and] = ACTIONS(206),
    [anon_sym_xor] = ACTIONS(206),
    [anon_sym_CARET_CARET] = ACTIONS(206),
    [anon_sym_or] = ACTIONS(206),
    [anon_sym_PIPE_PIPE] = ACTIONS(206),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(206),
    [anon_sym_LPAREN] = ACTIONS(206),
    [anon_sym_RPAREN] = ACTIONS(206),
    [anon_sym_len] = ACTIONS(206),
    [anon_sym_ends_with] = ACTIONS(206),
    [anon_sym_lookup_json_string] = ACTIONS(206),
    [anon_sym_lower] = ACTIONS(206),
    [anon_sym_regex_replace] = ACTIONS(206),
    [anon_sym_remove_bytes] = ACTIONS(206),
    [anon_sym_starts_with] = ACTIONS(206),
    [anon_sym_to_string] = ACTIONS(206),
    [anon_sym_upper] = ACTIONS(206),
    [anon_sym_url_decode] = ACTIONS(206),
    [anon_sym_uuidv4] = ACTIONS(206),
    [anon_sym_true] = ACTIONS(206),
    [anon_sym_false] = ACTIONS(206),
    [anon_sym_not] = ACTIONS(206),
    [anon_sym_BANG] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(206),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(206),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(206),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(206),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(206),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(208),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(206),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(206),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(206),
    [anon_sym_ip_DOTsrc] = ACTIONS(208),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(206),
    [anon_sym_http_DOTcookie] = ACTIONS(206),
    [anon_sym_http_DOThost] = ACTIONS(206),
    [anon_sym_http_DOTreferer] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(208),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(206),
    [anon_sym_http_DOTuser_agent] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(206),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(206),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(206),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(206),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(206),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(206),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(206),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(206),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(206),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(206),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(206),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(206),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(208),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(206),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(206),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(206),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(206),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(208),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(206),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(206),
    [anon_sym_ssl] = ACTIONS(206),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(206),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(206),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(206),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(206),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(206),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(206),
  },
  [42] = {
    [ts_builtin_sym_end] = ACTIONS(210),
    [anon_sym_AMP_AMP] = ACTIONS(178),
    [anon_sym_and] = ACTIONS(178),
    [anon_sym_xor] = ACTIONS(180),
    [anon_sym_CARET_CARET] = ACTIONS(180),
    [anon_sym_or] = ACTIONS(212),
    [anon_sym_PIPE_PIPE] = ACTIONS(212),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(210),
    [anon_sym_LPAREN] = ACTIONS(210),
    [anon_sym_len] = ACTIONS(210),
    [anon_sym_ends_with] = ACTIONS(210),
    [anon_sym_lookup_json_string] = ACTIONS(210),
    [anon_sym_lower] = ACTIONS(210),
    [anon_sym_regex_replace] = ACTIONS(210),
    [anon_sym_remove_bytes] = ACTIONS(210),
    [anon_sym_starts_with] = ACTIONS(210),
    [anon_sym_to_string] = ACTIONS(210),
    [anon_sym_upper] = ACTIONS(210),
    [anon_sym_url_decode] = ACTIONS(210),
    [anon_sym_uuidv4] = ACTIONS(210),
    [anon_sym_true] = ACTIONS(210),
    [anon_sym_false] = ACTIONS(210),
    [anon_sym_not] = ACTIONS(210),
    [anon_sym_BANG] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(210),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(210),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(210),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(210),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(210),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(214),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(210),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(210),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(210),
    [anon_sym_ip_DOTsrc] = ACTIONS(214),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(210),
    [anon_sym_http_DOTcookie] = ACTIONS(210),
    [anon_sym_http_DOThost] = ACTIONS(210),
    [anon_sym_http_DOTreferer] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(214),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(210),
    [anon_sym_http_DOTuser_agent] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(210),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(210),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(210),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(210),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(210),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(210),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(210),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(210),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(210),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(210),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(210),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(210),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(214),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(210),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(210),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(210),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(210),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(214),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(210),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(210),
    [anon_sym_ssl] = ACTIONS(210),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(210),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(210),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(210),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(210),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(210),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(210),
  },
  [43] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(216),
    [anon_sym_LPAREN] = ACTIONS(216),
    [anon_sym_len] = ACTIONS(216),
    [anon_sym_ends_with] = ACTIONS(216),
    [anon_sym_lookup_json_string] = ACTIONS(216),
    [anon_sym_lower] = ACTIONS(216),
    [anon_sym_regex_replace] = ACTIONS(216),
    [anon_sym_remove_bytes] = ACTIONS(216),
    [anon_sym_starts_with] = ACTIONS(216),
    [anon_sym_to_string] = ACTIONS(216),
    [anon_sym_upper] = ACTIONS(216),
    [anon_sym_url_decode] = ACTIONS(216),
    [anon_sym_uuidv4] = ACTIONS(216),
    [anon_sym_true] = ACTIONS(216),
    [anon_sym_false] = ACTIONS(216),
    [anon_sym_not] = ACTIONS(216),
    [anon_sym_BANG] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(216),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(216),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(216),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(216),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(216),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(218),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(216),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(216),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(216),
    [anon_sym_ip_DOTsrc] = ACTIONS(218),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(216),
    [anon_sym_http_DOTcookie] = ACTIONS(216),
    [anon_sym_http_DOThost] = ACTIONS(216),
    [anon_sym_http_DOTreferer] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(218),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(216),
    [anon_sym_http_DOTuser_agent] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(216),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(216),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(216),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(216),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(216),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(216),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(216),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(216),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(216),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(216),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(216),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(216),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(218),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(216),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(216),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(216),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(216),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(218),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(216),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(216),
    [anon_sym_ssl] = ACTIONS(216),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(216),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(216),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(216),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(216),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(216),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(216),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(222), 6,
      anon_sym_le,
      anon_sym_LT,
      anon_sym_GT,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(220), 48,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
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
      anon_sym_len,
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
  [62] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(226), 6,
      anon_sym_le,
      anon_sym_LT,
      anon_sym_GT,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(224), 48,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_lt,
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
      anon_sym_len,
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
  [124] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(232), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(106), 1,
      sym_array_string_field,
    STATE(130), 1,
      sym__array_lhs,
    STATE(171), 1,
      sym_bytes_field,
    STATE(175), 1,
      sym_array_field_expansion,
    STATE(177), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(173), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(234), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [198] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(236), 1,
      anon_sym_RPAREN,
    ACTIONS(238), 1,
      sym_string,
    STATE(49), 1,
      aux_sym_string_func_repeat1,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(64), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [270] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(238), 1,
      sym_string,
    ACTIONS(240), 1,
      anon_sym_RPAREN,
    STATE(49), 1,
      aux_sym_string_func_repeat1,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(64), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [342] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(242), 1,
      anon_sym_concat,
    ACTIONS(245), 1,
      anon_sym_RPAREN,
    ACTIONS(247), 1,
      anon_sym_len,
    ACTIONS(250), 1,
      sym_string,
    ACTIONS(259), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(262), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    STATE(49), 1,
      aux_sym_string_func_repeat1,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(256), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(64), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(265), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(253), 25,
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
  [414] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(238), 1,
      sym_string,
    ACTIONS(268), 1,
      anon_sym_RPAREN,
    STATE(49), 1,
      aux_sym_string_func_repeat1,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(64), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [486] = 14,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(270), 1,
      sym_string,
    STATE(106), 1,
      sym_array_string_field,
    STATE(130), 1,
      sym__array_lhs,
    STATE(177), 1,
      sym_map_string_array_field,
    STATE(183), 1,
      sym_array_field_expansion,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(180), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(234), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [557] = 13,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(232), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(128), 1,
      sym_map_string_array_field,
    STATE(156), 1,
      sym_bytes_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(119), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [626] = 13,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(238), 1,
      sym_string,
    STATE(47), 1,
      aux_sym_string_func_repeat1,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(64), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [695] = 13,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(238), 1,
      sym_string,
    STATE(48), 1,
      aux_sym_string_func_repeat1,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(64), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [764] = 13,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    ACTIONS(238), 1,
      sym_string,
    STATE(50), 1,
      aux_sym_string_func_repeat1,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(64), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [833] = 11,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(164), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [896] = 11,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(150), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [959] = 11,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(165), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [1022] = 11,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(146), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [1085] = 11,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(147), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [1148] = 11,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(100), 2,
      sym__stringlike_field,
      sym_string_field,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [1211] = 11,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(228), 1,
      anon_sym_concat,
    ACTIONS(230), 1,
      anon_sym_len,
    STATE(128), 1,
      sym_map_string_array_field,
    ACTIONS(47), 2,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    STATE(130), 2,
      sym__array_lhs,
      sym_array_string_field,
    STATE(163), 2,
      sym__stringlike_field,
      sym_string_field,
    ACTIONS(53), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
    ACTIONS(45), 25,
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
  [1274] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(274), 1,
      anon_sym_COMMA,
    ACTIONS(276), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(272), 33,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_len,
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
  [1321] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(280), 1,
      anon_sym_COMMA,
    ACTIONS(282), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(278), 33,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_len,
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
  [1368] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(286), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(284), 33,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_len,
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
  [1412] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(290), 3,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
      anon_sym_http_DOTrequest_DOTheaders,
    ACTIONS(288), 33,
      anon_sym_concat,
      anon_sym_RPAREN,
      anon_sym_len,
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
  [1456] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(39), 1,
      anon_sym_cf_DOTwaf_DOTscore,
    ACTIONS(43), 2,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
    STATE(148), 3,
      sym_number_field,
      sym_ip_field,
      sym_bool_field,
    ACTIONS(55), 8,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
      anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
    ACTIONS(37), 9,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
      anon_sym_ip_DOTgeoip_DOTasnum,
      anon_sym_cf_DOTbot_management_DOTscore,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTthreat_score,
      anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
      anon_sym_cf_DOTwaf_DOTscore_DOTxss,
      anon_sym_cf_DOTwaf_DOTscore_DOTrce,
  [1493] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(294), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(292), 14,
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
  [1517] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(298), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(296), 14,
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
  [1541] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(302), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(300), 14,
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
  [1565] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(306), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(304), 14,
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
  [1589] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(310), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(308), 14,
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
  [1613] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(314), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(312), 14,
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
  [1637] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(318), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(316), 14,
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
  [1661] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(322), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(320), 14,
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
  [1685] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(326), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(324), 14,
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
  [1709] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(330), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(328), 14,
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
  [1733] = 3,
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
  [1757] = 3,
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
  [1781] = 3,
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
  [1805] = 17,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(344), 1,
      anon_sym_in,
    ACTIONS(346), 1,
      anon_sym_eq,
    ACTIONS(348), 1,
      anon_sym_ne,
    ACTIONS(350), 1,
      anon_sym_lt,
    ACTIONS(352), 1,
      anon_sym_le,
    ACTIONS(354), 1,
      anon_sym_gt,
    ACTIONS(356), 1,
      anon_sym_ge,
    ACTIONS(358), 1,
      anon_sym_EQ_EQ,
    ACTIONS(360), 1,
      anon_sym_BANG_EQ,
    ACTIONS(362), 1,
      anon_sym_LT,
    ACTIONS(364), 1,
      anon_sym_LT_EQ,
    ACTIONS(366), 1,
      anon_sym_GT,
    ACTIONS(368), 1,
      anon_sym_GT_EQ,
    ACTIONS(370), 1,
      anon_sym_contains,
    ACTIONS(372), 1,
      anon_sym_matches,
    ACTIONS(374), 1,
      anon_sym_TILDE,
  [1857] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(378), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(376), 12,
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
  [1879] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(382), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(380), 11,
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
  [1900] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(386), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(384), 11,
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
  [1921] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(388), 1,
      anon_sym_in,
    ACTIONS(392), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(390), 10,
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
  [1944] = 7,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    STATE(153), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_array_string_field,
    STATE(183), 1,
      sym_array_field_expansion,
    ACTIONS(234), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1968] = 7,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(49), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(51), 1,
      anon_sym_http_DOTrequest_DOTheaders,
    STATE(153), 1,
      sym_map_string_array_field,
    STATE(154), 1,
      sym_array_string_field,
    STATE(175), 1,
      sym_array_field_expansion,
    ACTIONS(234), 3,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
  [1992] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(394), 1,
      anon_sym_RPAREN,
    ACTIONS(178), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(180), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(212), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [2011] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(396), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [2023] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(398), 1,
      anon_sym_in,
    ACTIONS(400), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [2036] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(402), 1,
      anon_sym_RBRACE,
    ACTIONS(404), 1,
      sym_ipv4,
    STATE(91), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [2051] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(407), 1,
      anon_sym_RBRACE,
    ACTIONS(409), 1,
      sym_ipv4,
    STATE(91), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [2066] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(411), 1,
      anon_sym_RPAREN,
    STATE(93), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(413), 2,
      sym_number,
      sym_string,
  [2080] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(416), 1,
      anon_sym_RPAREN,
    STATE(93), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [2094] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(420), 1,
      anon_sym_COMMA,
    ACTIONS(422), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [2106] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 1,
      sym_ipv4,
    STATE(92), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [2118] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(424), 1,
      anon_sym_RBRACE,
    ACTIONS(426), 1,
      sym_string,
    STATE(103), 1,
      aux_sym_string_set_repeat1,
  [2131] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(428), 1,
      anon_sym_RBRACE,
    ACTIONS(430), 1,
      sym_number,
    STATE(101), 1,
      aux_sym_number_set_repeat1,
  [2144] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(432), 1,
      anon_sym_LBRACE,
    ACTIONS(434), 1,
      sym_ip_list,
    STATE(22), 1,
      sym_ip_set,
  [2157] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(94), 1,
      aux_sym_lookup_func_repeat1,
    ACTIONS(418), 2,
      sym_number,
      sym_string,
  [2168] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(436), 1,
      anon_sym_RBRACE,
    ACTIONS(438), 1,
      sym_number,
    STATE(101), 1,
      aux_sym_number_set_repeat1,
  [2181] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 1,
      sym_ipv4,
    STATE(23), 2,
      sym__ip,
      sym_ip_range,
  [2192] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(441), 1,
      anon_sym_RBRACE,
    ACTIONS(443), 1,
      sym_string,
    STATE(103), 1,
      aux_sym_string_set_repeat1,
  [2205] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(411), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [2214] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(446), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [2222] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(448), 1,
      anon_sym_LBRACK,
    ACTIONS(450), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2232] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(452), 2,
      sym_string,
      anon_sym_STAR,
  [2240] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(454), 1,
      anon_sym_LBRACK,
    ACTIONS(456), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2250] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(452), 1,
      anon_sym_STAR,
    ACTIONS(458), 1,
      sym_string,
  [2260] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(460), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [2268] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      anon_sym_LBRACK,
    ACTIONS(464), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2278] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(466), 1,
      sym_string,
    STATE(97), 1,
      aux_sym_string_set_repeat1,
  [2288] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(468), 1,
      anon_sym_LBRACE,
    STATE(24), 1,
      sym_string_set,
  [2298] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(470), 1,
      sym_number,
    STATE(98), 1,
      aux_sym_number_set_repeat1,
  [2308] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(472), 1,
      anon_sym_LBRACE,
    STATE(22), 1,
      sym_number_set,
  [2318] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(232), 1,
      anon_sym_cf_DOTrandom_seed,
    STATE(145), 1,
      sym_bytes_field,
  [2328] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(474), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [2336] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(476), 1,
      sym_string,
  [2343] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(478), 1,
      anon_sym_COMMA,
  [2350] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(480), 1,
      sym_string,
  [2357] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(482), 1,
      sym_string,
  [2364] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(484), 1,
      sym_string,
  [2371] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(486), 1,
      sym_string,
  [2378] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      sym_string,
  [2385] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(490), 1,
      sym_string,
  [2392] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(492), 1,
      sym_string,
  [2399] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      sym_number,
  [2406] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(496), 1,
      anon_sym_LBRACK,
  [2413] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(498), 1,
      anon_sym_RBRACK,
  [2420] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(500), 1,
      anon_sym_LBRACK,
  [2427] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(502), 1,
      anon_sym_RBRACK,
  [2434] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(504), 1,
      anon_sym_LBRACK,
  [2441] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(506), 1,
      sym_string,
  [2448] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(508), 1,
      sym_string,
  [2455] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      sym_string,
  [2462] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(512), 1,
      sym_string,
  [2469] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      sym_string,
  [2476] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(516), 1,
      sym_string,
  [2483] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(518), 1,
      sym_string,
  [2490] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(520), 1,
      sym_string,
  [2497] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(522), 1,
      sym_string,
  [2504] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      sym_string,
  [2511] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(526), 1,
      anon_sym_LPAREN,
  [2518] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      ts_builtin_sym_end,
  [2525] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(530), 1,
      anon_sym_RPAREN,
  [2532] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(532), 1,
      anon_sym_RPAREN,
  [2539] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(534), 1,
      anon_sym_RPAREN,
  [2546] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(536), 1,
      anon_sym_RPAREN,
  [2553] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(456), 1,
      anon_sym_LBRACK,
  [2560] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      anon_sym_COMMA,
  [2567] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(540), 1,
      aux_sym_ip_range_token1,
  [2574] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      anon_sym_LBRACK,
  [2581] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(544), 1,
      anon_sym_LBRACK,
  [2588] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(450), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2595] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(546), 1,
      anon_sym_LBRACK,
  [2602] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(548), 1,
      anon_sym_COMMA,
  [2609] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(550), 1,
      sym_string,
  [2616] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(552), 1,
      anon_sym_LPAREN,
  [2623] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(554), 1,
      anon_sym_LPAREN,
  [2630] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(556), 1,
      anon_sym_RBRACK,
  [2637] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      anon_sym_RBRACK,
  [2644] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(560), 1,
      anon_sym_RPAREN,
  [2651] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      anon_sym_COMMA,
  [2658] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(564), 1,
      anon_sym_RPAREN,
  [2665] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      anon_sym_COMMA,
  [2672] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(568), 1,
      anon_sym_COMMA,
  [2679] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_RPAREN,
  [2686] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(572), 1,
      anon_sym_RPAREN,
  [2693] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(574), 1,
      anon_sym_RPAREN,
  [2700] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(576), 1,
      anon_sym_LPAREN,
  [2707] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(578), 1,
      anon_sym_RPAREN,
  [2714] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(580), 1,
      anon_sym_LPAREN,
  [2721] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(582), 1,
      anon_sym_RPAREN,
  [2728] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(584), 1,
      anon_sym_LPAREN,
  [2735] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(586), 1,
      anon_sym_RPAREN,
  [2742] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(588), 1,
      anon_sym_LPAREN,
  [2749] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(590), 1,
      anon_sym_LBRACK,
  [2756] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(592), 1,
      anon_sym_LPAREN,
  [2763] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(594), 1,
      anon_sym_LPAREN,
  [2770] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(596), 1,
      anon_sym_COMMA,
  [2777] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(598), 1,
      anon_sym_LPAREN,
  [2784] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(600), 1,
      anon_sym_LBRACK,
  [2791] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      anon_sym_COMMA,
  [2798] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(604), 1,
      anon_sym_COMMA,
  [2805] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(464), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [2812] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      anon_sym_LPAREN,
  [2819] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(608), 1,
      sym_string,
  [2826] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(610), 1,
      anon_sym_LPAREN,
  [2833] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(612), 1,
      anon_sym_LPAREN,
  [2840] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(614), 1,
      anon_sym_LPAREN,
  [2847] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(616), 1,
      sym_string,
  [2854] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(618), 1,
      anon_sym_RPAREN,
  [2861] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(620), 1,
      sym_number,
  [2868] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(622), 1,
      sym_string,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(44)] = 0,
  [SMALL_STATE(45)] = 62,
  [SMALL_STATE(46)] = 124,
  [SMALL_STATE(47)] = 198,
  [SMALL_STATE(48)] = 270,
  [SMALL_STATE(49)] = 342,
  [SMALL_STATE(50)] = 414,
  [SMALL_STATE(51)] = 486,
  [SMALL_STATE(52)] = 557,
  [SMALL_STATE(53)] = 626,
  [SMALL_STATE(54)] = 695,
  [SMALL_STATE(55)] = 764,
  [SMALL_STATE(56)] = 833,
  [SMALL_STATE(57)] = 896,
  [SMALL_STATE(58)] = 959,
  [SMALL_STATE(59)] = 1022,
  [SMALL_STATE(60)] = 1085,
  [SMALL_STATE(61)] = 1148,
  [SMALL_STATE(62)] = 1211,
  [SMALL_STATE(63)] = 1274,
  [SMALL_STATE(64)] = 1321,
  [SMALL_STATE(65)] = 1368,
  [SMALL_STATE(66)] = 1412,
  [SMALL_STATE(67)] = 1456,
  [SMALL_STATE(68)] = 1493,
  [SMALL_STATE(69)] = 1517,
  [SMALL_STATE(70)] = 1541,
  [SMALL_STATE(71)] = 1565,
  [SMALL_STATE(72)] = 1589,
  [SMALL_STATE(73)] = 1613,
  [SMALL_STATE(74)] = 1637,
  [SMALL_STATE(75)] = 1661,
  [SMALL_STATE(76)] = 1685,
  [SMALL_STATE(77)] = 1709,
  [SMALL_STATE(78)] = 1733,
  [SMALL_STATE(79)] = 1757,
  [SMALL_STATE(80)] = 1781,
  [SMALL_STATE(81)] = 1805,
  [SMALL_STATE(82)] = 1857,
  [SMALL_STATE(83)] = 1879,
  [SMALL_STATE(84)] = 1900,
  [SMALL_STATE(85)] = 1921,
  [SMALL_STATE(86)] = 1944,
  [SMALL_STATE(87)] = 1968,
  [SMALL_STATE(88)] = 1992,
  [SMALL_STATE(89)] = 2011,
  [SMALL_STATE(90)] = 2023,
  [SMALL_STATE(91)] = 2036,
  [SMALL_STATE(92)] = 2051,
  [SMALL_STATE(93)] = 2066,
  [SMALL_STATE(94)] = 2080,
  [SMALL_STATE(95)] = 2094,
  [SMALL_STATE(96)] = 2106,
  [SMALL_STATE(97)] = 2118,
  [SMALL_STATE(98)] = 2131,
  [SMALL_STATE(99)] = 2144,
  [SMALL_STATE(100)] = 2157,
  [SMALL_STATE(101)] = 2168,
  [SMALL_STATE(102)] = 2181,
  [SMALL_STATE(103)] = 2192,
  [SMALL_STATE(104)] = 2205,
  [SMALL_STATE(105)] = 2214,
  [SMALL_STATE(106)] = 2222,
  [SMALL_STATE(107)] = 2232,
  [SMALL_STATE(108)] = 2240,
  [SMALL_STATE(109)] = 2250,
  [SMALL_STATE(110)] = 2260,
  [SMALL_STATE(111)] = 2268,
  [SMALL_STATE(112)] = 2278,
  [SMALL_STATE(113)] = 2288,
  [SMALL_STATE(114)] = 2298,
  [SMALL_STATE(115)] = 2308,
  [SMALL_STATE(116)] = 2318,
  [SMALL_STATE(117)] = 2328,
  [SMALL_STATE(118)] = 2336,
  [SMALL_STATE(119)] = 2343,
  [SMALL_STATE(120)] = 2350,
  [SMALL_STATE(121)] = 2357,
  [SMALL_STATE(122)] = 2364,
  [SMALL_STATE(123)] = 2371,
  [SMALL_STATE(124)] = 2378,
  [SMALL_STATE(125)] = 2385,
  [SMALL_STATE(126)] = 2392,
  [SMALL_STATE(127)] = 2399,
  [SMALL_STATE(128)] = 2406,
  [SMALL_STATE(129)] = 2413,
  [SMALL_STATE(130)] = 2420,
  [SMALL_STATE(131)] = 2427,
  [SMALL_STATE(132)] = 2434,
  [SMALL_STATE(133)] = 2441,
  [SMALL_STATE(134)] = 2448,
  [SMALL_STATE(135)] = 2455,
  [SMALL_STATE(136)] = 2462,
  [SMALL_STATE(137)] = 2469,
  [SMALL_STATE(138)] = 2476,
  [SMALL_STATE(139)] = 2483,
  [SMALL_STATE(140)] = 2490,
  [SMALL_STATE(141)] = 2497,
  [SMALL_STATE(142)] = 2504,
  [SMALL_STATE(143)] = 2511,
  [SMALL_STATE(144)] = 2518,
  [SMALL_STATE(145)] = 2525,
  [SMALL_STATE(146)] = 2532,
  [SMALL_STATE(147)] = 2539,
  [SMALL_STATE(148)] = 2546,
  [SMALL_STATE(149)] = 2553,
  [SMALL_STATE(150)] = 2560,
  [SMALL_STATE(151)] = 2567,
  [SMALL_STATE(152)] = 2574,
  [SMALL_STATE(153)] = 2581,
  [SMALL_STATE(154)] = 2588,
  [SMALL_STATE(155)] = 2595,
  [SMALL_STATE(156)] = 2602,
  [SMALL_STATE(157)] = 2609,
  [SMALL_STATE(158)] = 2616,
  [SMALL_STATE(159)] = 2623,
  [SMALL_STATE(160)] = 2630,
  [SMALL_STATE(161)] = 2637,
  [SMALL_STATE(162)] = 2644,
  [SMALL_STATE(163)] = 2651,
  [SMALL_STATE(164)] = 2658,
  [SMALL_STATE(165)] = 2665,
  [SMALL_STATE(166)] = 2672,
  [SMALL_STATE(167)] = 2679,
  [SMALL_STATE(168)] = 2686,
  [SMALL_STATE(169)] = 2693,
  [SMALL_STATE(170)] = 2700,
  [SMALL_STATE(171)] = 2707,
  [SMALL_STATE(172)] = 2714,
  [SMALL_STATE(173)] = 2721,
  [SMALL_STATE(174)] = 2728,
  [SMALL_STATE(175)] = 2735,
  [SMALL_STATE(176)] = 2742,
  [SMALL_STATE(177)] = 2749,
  [SMALL_STATE(178)] = 2756,
  [SMALL_STATE(179)] = 2763,
  [SMALL_STATE(180)] = 2770,
  [SMALL_STATE(181)] = 2777,
  [SMALL_STATE(182)] = 2784,
  [SMALL_STATE(183)] = 2791,
  [SMALL_STATE(184)] = 2798,
  [SMALL_STATE(185)] = 2805,
  [SMALL_STATE(186)] = 2812,
  [SMALL_STATE(187)] = 2819,
  [SMALL_STATE(188)] = 2826,
  [SMALL_STATE(189)] = 2833,
  [SMALL_STATE(190)] = 2840,
  [SMALL_STATE(191)] = 2847,
  [SMALL_STATE(192)] = 2854,
  [SMALL_STATE(193)] = 2861,
  [SMALL_STATE(194)] = 2868,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(143),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(190),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(186),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(181),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(179),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(178),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(176),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(174),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(172),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(170),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(159),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(158),
  [33] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [35] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [37] = {.entry = {.count = 1, .reusable = true}}, SHIFT(82),
  [39] = {.entry = {.count = 1, .reusable = false}}, SHIFT(82),
  [41] = {.entry = {.count = 1, .reusable = false}}, SHIFT(89),
  [43] = {.entry = {.count = 1, .reusable = true}}, SHIFT(89),
  [45] = {.entry = {.count = 1, .reusable = true}}, SHIFT(45),
  [47] = {.entry = {.count = 1, .reusable = false}}, SHIFT(45),
  [49] = {.entry = {.count = 1, .reusable = true}}, SHIFT(155),
  [51] = {.entry = {.count = 1, .reusable = false}}, SHIFT(155),
  [53] = {.entry = {.count = 1, .reusable = true}}, SHIFT(149),
  [55] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [57] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [59] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(143),
  [62] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(5),
  [65] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(190),
  [68] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(186),
  [71] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(181),
  [74] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(179),
  [77] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(178),
  [80] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(176),
  [83] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(174),
  [86] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(172),
  [89] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(170),
  [92] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(159),
  [95] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(158),
  [98] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(19),
  [101] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(43),
  [104] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(82),
  [107] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(82),
  [110] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(89),
  [113] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(89),
  [116] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(45),
  [119] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(45),
  [122] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(155),
  [125] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(155),
  [128] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(149),
  [131] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(25),
  [134] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [136] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [138] = {.entry = {.count = 1, .reusable = true}}, SHIFT(151),
  [140] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [142] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [144] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [146] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 4),
  [148] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 4),
  [150] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [152] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [154] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [156] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [158] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [160] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [162] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ends_with_func, 6, .production_id = 18),
  [164] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ends_with_func, 6, .production_id = 18),
  [166] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [168] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [170] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 3),
  [172] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 3),
  [174] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [176] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [178] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [180] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [182] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 3),
  [184] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 3),
  [186] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 3),
  [188] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 3),
  [190] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 4),
  [192] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 4),
  [194] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_field, 1),
  [196] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_field, 1),
  [198] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 1),
  [200] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 1),
  [202] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3, .production_id = 2),
  [204] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3, .production_id = 2),
  [206] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_starts_with_func, 6, .production_id = 18),
  [208] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_starts_with_func, 6, .production_id = 18),
  [210] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [212] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [214] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [216] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [218] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [220] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__stringlike_field, 4, .production_id = 10),
  [222] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__stringlike_field, 4, .production_id = 10),
  [224] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [226] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [228] = {.entry = {.count = 1, .reusable = true}}, SHIFT(189),
  [230] = {.entry = {.count = 1, .reusable = true}}, SHIFT(188),
  [232] = {.entry = {.count = 1, .reusable = true}}, SHIFT(105),
  [234] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [236] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [238] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [240] = {.entry = {.count = 1, .reusable = true}}, SHIFT(182),
  [242] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(189),
  [245] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15),
  [247] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(188),
  [250] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(63),
  [253] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(45),
  [256] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(45),
  [259] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(155),
  [262] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(155),
  [265] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 15), SHIFT_REPEAT(149),
  [268] = {.entry = {.count = 1, .reusable = true}}, SHIFT(79),
  [270] = {.entry = {.count = 1, .reusable = true}}, SHIFT(184),
  [272] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [274] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [276] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [278] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [280] = {.entry = {.count = 1, .reusable = true}}, SHIFT(65),
  [282] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1, .production_id = 1),
  [284] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [286] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2, .production_id = 1),
  [288] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [290] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [292] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_upper_func, 4, .production_id = 7),
  [294] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_upper_func, 4, .production_id = 7),
  [296] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_lower_func, 4, .production_id = 7),
  [298] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_lower_func, 4, .production_id = 7),
  [300] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_uuid_func, 4, .production_id = 9),
  [302] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_uuid_func, 4, .production_id = 9),
  [304] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_regex_replace_func, 8, .production_id = 21),
  [306] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_regex_replace_func, 8, .production_id = 21),
  [308] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 1),
  [310] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 1),
  [312] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_lookup_func, 5, .production_id = 12),
  [314] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_lookup_func, 5, .production_id = 12),
  [316] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_url_decode_func, 4, .production_id = 7),
  [318] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_url_decode_func, 4, .production_id = 7),
  [320] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 20),
  [322] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 20),
  [324] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 19),
  [326] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_remove_bytes_func, 6, .production_id = 19),
  [328] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_to_string_func, 4, .production_id = 8),
  [330] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_to_string_func, 4, .production_id = 8),
  [332] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 17),
  [334] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 17),
  [336] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 14),
  [338] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 14),
  [340] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [342] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__string_lhs, 1, .production_id = 1),
  [344] = {.entry = {.count = 1, .reusable = true}}, SHIFT(113),
  [346] = {.entry = {.count = 1, .reusable = true}}, SHIFT(126),
  [348] = {.entry = {.count = 1, .reusable = true}}, SHIFT(125),
  [350] = {.entry = {.count = 1, .reusable = true}}, SHIFT(124),
  [352] = {.entry = {.count = 1, .reusable = true}}, SHIFT(123),
  [354] = {.entry = {.count = 1, .reusable = true}}, SHIFT(122),
  [356] = {.entry = {.count = 1, .reusable = true}}, SHIFT(121),
  [358] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [360] = {.entry = {.count = 1, .reusable = true}}, SHIFT(157),
  [362] = {.entry = {.count = 1, .reusable = false}}, SHIFT(134),
  [364] = {.entry = {.count = 1, .reusable = true}}, SHIFT(136),
  [366] = {.entry = {.count = 1, .reusable = false}}, SHIFT(137),
  [368] = {.entry = {.count = 1, .reusable = true}}, SHIFT(118),
  [370] = {.entry = {.count = 1, .reusable = true}}, SHIFT(138),
  [372] = {.entry = {.count = 1, .reusable = true}}, SHIFT(133),
  [374] = {.entry = {.count = 1, .reusable = true}}, SHIFT(194),
  [376] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [378] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [380] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 6),
  [382] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 6),
  [384] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 5),
  [386] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 5),
  [388] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [390] = {.entry = {.count = 1, .reusable = true}}, SHIFT(127),
  [392] = {.entry = {.count = 1, .reusable = false}}, SHIFT(127),
  [394] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [396] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [398] = {.entry = {.count = 1, .reusable = true}}, SHIFT(99),
  [400] = {.entry = {.count = 1, .reusable = true}}, SHIFT(102),
  [402] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [404] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(9),
  [407] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [409] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [411] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 2),
  [413] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 2), SHIFT_REPEAT(95),
  [416] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [418] = {.entry = {.count = 1, .reusable = true}}, SHIFT(95),
  [420] = {.entry = {.count = 1, .reusable = true}}, SHIFT(104),
  [422] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_lookup_func_repeat1, 1),
  [424] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [426] = {.entry = {.count = 1, .reusable = true}}, SHIFT(103),
  [428] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [430] = {.entry = {.count = 1, .reusable = true}}, SHIFT(101),
  [432] = {.entry = {.count = 1, .reusable = true}}, SHIFT(96),
  [434] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [436] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [438] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(101),
  [441] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [443] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(103),
  [446] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [448] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 1),
  [450] = {.entry = {.count = 1, .reusable = true}}, SHIFT(110),
  [452] = {.entry = {.count = 1, .reusable = true}}, SHIFT(161),
  [454] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_string_field, 1),
  [456] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_string_field, 1),
  [458] = {.entry = {.count = 1, .reusable = true}}, SHIFT(160),
  [460] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_field_expansion, 2),
  [462] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__array_lhs, 4, .production_id = 11),
  [464] = {.entry = {.count = 1, .reusable = true}}, SHIFT(117),
  [466] = {.entry = {.count = 1, .reusable = true}}, SHIFT(97),
  [468] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [470] = {.entry = {.count = 1, .reusable = true}}, SHIFT(98),
  [472] = {.entry = {.count = 1, .reusable = true}}, SHIFT(114),
  [474] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_field_expansion, 5, .production_id = 11),
  [476] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [478] = {.entry = {.count = 1, .reusable = true}}, SHIFT(140),
  [480] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [482] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [484] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [486] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [488] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [490] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [492] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [494] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [496] = {.entry = {.count = 1, .reusable = true}}, SHIFT(191),
  [498] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [500] = {.entry = {.count = 1, .reusable = true}}, SHIFT(193),
  [502] = {.entry = {.count = 1, .reusable = true}}, SHIFT(152),
  [504] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 4, .production_id = 5),
  [506] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [508] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [510] = {.entry = {.count = 1, .reusable = true}}, SHIFT(162),
  [512] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [514] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [516] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [518] = {.entry = {.count = 1, .reusable = true}}, SHIFT(166),
  [520] = {.entry = {.count = 1, .reusable = true}}, SHIFT(167),
  [522] = {.entry = {.count = 1, .reusable = true}}, SHIFT(168),
  [524] = {.entry = {.count = 1, .reusable = true}}, SHIFT(169),
  [526] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [528] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [530] = {.entry = {.count = 1, .reusable = true}}, SHIFT(70),
  [532] = {.entry = {.count = 1, .reusable = true}}, SHIFT(74),
  [534] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [536] = {.entry = {.count = 1, .reusable = true}}, SHIFT(77),
  [538] = {.entry = {.count = 1, .reusable = true}}, SHIFT(142),
  [540] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [542] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 4, .production_id = 11),
  [544] = {.entry = {.count = 1, .reusable = true}}, SHIFT(107),
  [546] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_map_string_array_field, 1),
  [548] = {.entry = {.count = 1, .reusable = true}}, SHIFT(141),
  [550] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [552] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [554] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [556] = {.entry = {.count = 1, .reusable = true}}, SHIFT(111),
  [558] = {.entry = {.count = 1, .reusable = true}}, SHIFT(185),
  [560] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [562] = {.entry = {.count = 1, .reusable = true}}, SHIFT(139),
  [564] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [566] = {.entry = {.count = 1, .reusable = true}}, SHIFT(135),
  [568] = {.entry = {.count = 1, .reusable = true}}, SHIFT(187),
  [570] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [572] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [574] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [576] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [578] = {.entry = {.count = 1, .reusable = true}}, SHIFT(84),
  [580] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
  [582] = {.entry = {.count = 1, .reusable = true}}, SHIFT(83),
  [584] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [586] = {.entry = {.count = 1, .reusable = true}}, SHIFT(132),
  [588] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [590] = {.entry = {.count = 1, .reusable = true}}, SHIFT(109),
  [592] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [594] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [596] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [598] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [600] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__array_lhs, 6, .production_id = 16),
  [602] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [604] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [606] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [608] = {.entry = {.count = 1, .reusable = true}}, SHIFT(192),
  [610] = {.entry = {.count = 1, .reusable = true}}, SHIFT(87),
  [612] = {.entry = {.count = 1, .reusable = true}}, SHIFT(86),
  [614] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [616] = {.entry = {.count = 1, .reusable = true}}, SHIFT(131),
  [618] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [620] = {.entry = {.count = 1, .reusable = true}}, SHIFT(129),
  [622] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
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
