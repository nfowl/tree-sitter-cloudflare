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
#define STATE_COUNT 51
#define LARGE_STATE_COUNT 25
#define SYMBOL_COUNT 107
#define ALIAS_COUNT 0
#define TOKEN_COUNT 85
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 7
#define MAX_ALIAS_SEQUENCE_LENGTH 3
#define PRODUCTION_ID_COUNT 4

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
  anon_sym_LPAREN = 26,
  anon_sym_RPAREN = 27,
  sym_number = 28,
  sym_string = 29,
  anon_sym_true = 30,
  anon_sym_false = 31,
  sym_ipv4 = 32,
  anon_sym_SLASH = 33,
  aux_sym_ip_range_token1 = 34,
  anon_sym_not = 35,
  anon_sym_BANG = 36,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTsec = 37,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec = 38,
  anon_sym_ip_DOTgeoip_DOTasnum = 39,
  anon_sym_cf_DOTbot_management_DOTscore = 40,
  anon_sym_cf_DOTedge_DOTserver_port = 41,
  anon_sym_cf_DOTthreat_score = 42,
  anon_sym_cf_DOTwaf_DOTscore = 43,
  anon_sym_cf_DOTwaf_DOTscore_DOTsqli = 44,
  anon_sym_cf_DOTwaf_DOTscore_DOTxss = 45,
  anon_sym_cf_DOTwaf_DOTscore_DOTrce = 46,
  anon_sym_ip_DOTsrc = 47,
  anon_sym_cf_DOTedge_DOTserver_ip = 48,
  anon_sym_http_DOTcookie = 49,
  anon_sym_http_DOThost = 50,
  anon_sym_http_DOTreferer = 51,
  anon_sym_http_DOTrequest_DOTfull_uri = 52,
  anon_sym_http_DOTrequest_DOTmethod = 53,
  anon_sym_http_DOTrequest_DOTcookies = 54,
  anon_sym_http_DOTrequest_DOTuri = 55,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 56,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 57,
  anon_sym_http_DOTuser_agent = 58,
  anon_sym_http_DOTrequest_DOTversion = 59,
  anon_sym_http_DOTx_forwarded_for = 60,
  anon_sym_ip_DOTsrc_DOTlat = 61,
  anon_sym_ip_DOTsrc_DOTlon = 62,
  anon_sym_ip_DOTsrc_DOTcity = 63,
  anon_sym_ip_DOTsrc_DOTpostal_code = 64,
  anon_sym_ip_DOTsrc_DOTmetro_code = 65,
  anon_sym_ip_DOTgeoip_DOTcontinent = 66,
  anon_sym_ip_DOTgeoip_DOTcountry = 67,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 68,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 69,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 70,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 71,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 72,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 73,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 74,
  anon_sym_cf_DOThostname_DOTmetadata = 75,
  anon_sym_cf_DOTworker_DOTupstream_zone = 76,
  anon_sym_cf_DOTrandom_seed = 77,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 78,
  anon_sym_ssl = 79,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 80,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 81,
  anon_sym_cf_DOTclient_DOTbot = 82,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 83,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 84,
  sym_source_file = 85,
  sym__expression = 86,
  sym_not_expression = 87,
  sym_in_expression = 88,
  sym_compound_expression = 89,
  sym_ip_set = 90,
  sym_string_set = 91,
  sym_number_set = 92,
  sym_simple_expression = 93,
  sym_group = 94,
  sym_boolean = 95,
  sym__ip = 96,
  sym_ip_range = 97,
  sym_not_operator = 98,
  sym_number_field = 99,
  sym_ip_field = 100,
  sym_string_field = 101,
  sym_boolean_field = 102,
  aux_sym_source_file_repeat1 = 103,
  aux_sym_ip_set_repeat1 = 104,
  aux_sym_string_set_repeat1 = 105,
  aux_sym_number_set_repeat1 = 106,
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
  [anon_sym_LPAREN] = "(",
  [anon_sym_RPAREN] = ")",
  [sym_number] = "number",
  [sym_string] = "string",
  [anon_sym_true] = "true",
  [anon_sym_false] = "false",
  [sym_ipv4] = "ipv4",
  [anon_sym_SLASH] = "/",
  [aux_sym_ip_range_token1] = "ip_range_token1",
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
  [sym_group] = "group",
  [sym_boolean] = "boolean",
  [sym__ip] = "_ip",
  [sym_ip_range] = "ip_range",
  [sym_not_operator] = "not_operator",
  [sym_number_field] = "number_field",
  [sym_ip_field] = "ip_field",
  [sym_string_field] = "string_field",
  [sym_boolean_field] = "boolean_field",
  [aux_sym_source_file_repeat1] = "source_file_repeat1",
  [aux_sym_ip_set_repeat1] = "ip_set_repeat1",
  [aux_sym_string_set_repeat1] = "string_set_repeat1",
  [aux_sym_number_set_repeat1] = "number_set_repeat1",
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
  [anon_sym_LPAREN] = anon_sym_LPAREN,
  [anon_sym_RPAREN] = anon_sym_RPAREN,
  [sym_number] = sym_number,
  [sym_string] = sym_string,
  [anon_sym_true] = anon_sym_true,
  [anon_sym_false] = anon_sym_false,
  [sym_ipv4] = sym_ipv4,
  [anon_sym_SLASH] = anon_sym_SLASH,
  [aux_sym_ip_range_token1] = aux_sym_ip_range_token1,
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
  [sym_group] = sym_group,
  [sym_boolean] = sym_boolean,
  [sym__ip] = sym__ip,
  [sym_ip_range] = sym_ip_range,
  [sym_not_operator] = sym_not_operator,
  [sym_number_field] = sym_number_field,
  [sym_ip_field] = sym_ip_field,
  [sym_string_field] = sym_string_field,
  [sym_boolean_field] = sym_boolean_field,
  [aux_sym_source_file_repeat1] = aux_sym_source_file_repeat1,
  [aux_sym_ip_set_repeat1] = aux_sym_ip_set_repeat1,
  [aux_sym_string_set_repeat1] = aux_sym_string_set_repeat1,
  [aux_sym_number_set_repeat1] = aux_sym_number_set_repeat1,
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
  [anon_sym_LPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RPAREN] = {
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
};

enum {
  field_field = 1,
  field_ip = 2,
  field_left = 3,
  field_mask = 4,
  field_operator = 5,
  field_right = 6,
  field_value = 7,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_field] = "field",
  [field_ip] = "ip",
  [field_left] = "left",
  [field_mask] = "mask",
  [field_operator] = "operator",
  [field_right] = "right",
  [field_value] = "value",
};

static const TSFieldMapSlice ts_field_map_slices[PRODUCTION_ID_COUNT] = {
  [1] = {.index = 0, .length = 3},
  [2] = {.index = 3, .length = 3},
  [3] = {.index = 6, .length = 2},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_left, 0},
    {field_operator, 1},
    {field_right, 2},
  [3] =
    {field_field, 0},
    {field_operator, 1},
    {field_value, 2},
  [6] =
    {field_ip, 0},
    {field_mask, 2},
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
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(482);
      if (lookahead == '!') ADVANCE(526);
      if (lookahead == '"') ADVANCE(1);
      if (lookahead == '#') ADVANCE(492);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(508);
      if (lookahead == ')') ADVANCE(509);
      if (lookahead == '/') ADVANCE(520);
      if (lookahead == '3') ADVANCE(510);
      if (lookahead == '<') ADVANCE(501);
      if (lookahead == '=') ADVANCE(43);
      if (lookahead == '>') ADVANCE(503);
      if (lookahead == '^') ADVANCE(44);
      if (lookahead == 'a') ADVANCE(276);
      if (lookahead == 'c') ADVANCE(201);
      if (lookahead == 'e') ADVANCE(348);
      if (lookahead == 'f') ADVANCE(71);
      if (lookahead == 'g') ADVANCE(139);
      if (lookahead == 'h') ADVANCE(429);
      if (lookahead == 'i') ADVANCE(277);
      if (lookahead == 'l') ADVANCE(140);
      if (lookahead == 'm') ADVANCE(77);
      if (lookahead == 'n') ADVANCE(141);
      if (lookahead == 'o') ADVANCE(351);
      if (lookahead == 'r') ADVANCE(72);
      if (lookahead == 's') ADVANCE(391);
      if (lookahead == 't') ADVANCE(352);
      if (lookahead == 'x') ADVANCE(304);
      if (lookahead == '{') ADVANCE(490);
      if (lookahead == '|') ADVANCE(480);
      if (lookahead == '}') ADVANCE(491);
      if (lookahead == '~') ADVANCE(507);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(511);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(511);
      END_STATE();
    case 1:
      if (lookahead == '"') ADVANCE(512);
      if (lookahead != 0) ADVANCE(1);
      END_STATE();
    case 2:
      if (lookahead == '#') ADVANCE(492);
      if (lookahead == '3') ADVANCE(522);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(523);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(2)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(521);
      END_STATE();
    case 3:
      if (lookahead == '#') ADVANCE(492);
      if (lookahead == '}') ADVANCE(491);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(511);
      END_STATE();
    case 4:
      if (lookahead == '&') ADVANCE(484);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(98);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(210);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(108);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(82);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(101);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(120);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(209);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(251);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(273);
      END_STATE();
    case 14:
      if (lookahead == '.') ADVANCE(41);
      END_STATE();
    case 15:
      if (lookahead == '.') ADVANCE(41);
      if (lookahead == '5') ADVANCE(16);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(14);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(18);
      END_STATE();
    case 16:
      if (lookahead == '.') ADVANCE(41);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(14);
      END_STATE();
    case 17:
      if (lookahead == '.') ADVANCE(41);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(18);
      END_STATE();
    case 18:
      if (lookahead == '.') ADVANCE(41);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(14);
      END_STATE();
    case 19:
      if (lookahead == '.') ADVANCE(99);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(456);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(222);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(39);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(39);
      if (lookahead == '5') ADVANCE(24);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(22);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(26);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(39);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(22);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(39);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(26);
      END_STATE();
    case 26:
      if (lookahead == '.') ADVANCE(39);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(22);
      END_STATE();
    case 27:
      if (lookahead == '.') ADVANCE(343);
      END_STATE();
    case 28:
      if (lookahead == '.') ADVANCE(394);
      END_STATE();
    case 29:
      if (lookahead == '.') ADVANCE(40);
      END_STATE();
    case 30:
      if (lookahead == '.') ADVANCE(40);
      if (lookahead == '5') ADVANCE(31);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(29);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(33);
      END_STATE();
    case 31:
      if (lookahead == '.') ADVANCE(40);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(29);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(40);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(33);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(40);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(29);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(271);
      END_STATE();
    case 35:
      if (lookahead == '.') ADVANCE(112);
      END_STATE();
    case 36:
      if (lookahead == '.') ADVANCE(403);
      END_STATE();
    case 37:
      if (lookahead == '.') ADVANCE(378);
      END_STATE();
    case 38:
      if (lookahead == '1') ADVANCE(59);
      if (lookahead == '2') ADVANCE(70);
      END_STATE();
    case 39:
      if (lookahead == '2') ADVANCE(516);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(519);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(518);
      END_STATE();
    case 40:
      if (lookahead == '2') ADVANCE(23);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(25);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(26);
      END_STATE();
    case 41:
      if (lookahead == '2') ADVANCE(30);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(32);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(33);
      END_STATE();
    case 42:
      if (lookahead == '3') ADVANCE(53);
      END_STATE();
    case 43:
      if (lookahead == '=') ADVANCE(499);
      END_STATE();
    case 44:
      if (lookahead == '^') ADVANCE(487);
      END_STATE();
    case 45:
      if (lookahead == '_') ADVANCE(268);
      END_STATE();
    case 46:
      if (lookahead == '_') ADVANCE(230);
      END_STATE();
    case 47:
      if (lookahead == '_') ADVANCE(479);
      END_STATE();
    case 48:
      if (lookahead == '_') ADVANCE(38);
      END_STATE();
    case 49:
      if (lookahead == '_') ADVANCE(385);
      END_STATE();
    case 50:
      if (lookahead == '_') ADVANCE(205);
      END_STATE();
    case 51:
      if (lookahead == '_') ADVANCE(119);
      END_STATE();
    case 52:
      if (lookahead == '_') ADVANCE(109);
      END_STATE();
    case 53:
      if (lookahead == '_') ADVANCE(221);
      END_STATE();
    case 54:
      if (lookahead == '_') ADVANCE(460);
      END_STATE();
    case 55:
      if (lookahead == '_') ADVANCE(81);
      END_STATE();
    case 56:
      if (lookahead == '_') ADVANCE(163);
      END_STATE();
    case 57:
      if (lookahead == '_') ADVANCE(233);
      END_STATE();
    case 58:
      if (lookahead == '_') ADVANCE(463);
      END_STATE();
    case 59:
      if (lookahead == '_') ADVANCE(238);
      END_STATE();
    case 60:
      if (lookahead == '_') ADVANCE(465);
      END_STATE();
    case 61:
      if (lookahead == '_') ADVANCE(406);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(137);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(102);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(207);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(96);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(114);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(414);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(116);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(118);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(250);
      END_STATE();
    case 71:
      if (lookahead == 'a') ADVANCE(258);
      END_STATE();
    case 72:
      if (lookahead == 'a') ADVANCE(473);
      END_STATE();
    case 73:
      if (lookahead == 'a') ADVANCE(202);
      if (lookahead == 'o') ADVANCE(354);
      END_STATE();
    case 74:
      if (lookahead == 'a') ADVANCE(42);
      if (lookahead == 's') ADVANCE(62);
      END_STATE();
    case 75:
      if (lookahead == 'a') ADVANCE(565);
      END_STATE();
    case 76:
      if (lookahead == 'a') ADVANCE(229);
      END_STATE();
    case 77:
      if (lookahead == 'a') ADVANCE(418);
      END_STATE();
    case 78:
      if (lookahead == 'a') ADVANCE(270);
      END_STATE();
    case 79:
      if (lookahead == 'a') ADVANCE(265);
      END_STATE();
    case 80:
      if (lookahead == 'a') ADVANCE(272);
      END_STATE();
    case 81:
      if (lookahead == 'a') ADVANCE(464);
      END_STATE();
    case 82:
      if (lookahead == 'a') ADVANCE(395);
      if (lookahead == 'c') ADVANCE(301);
      if (lookahead == 'i') ADVANCE(397);
      if (lookahead == 's') ADVANCE(457);
      END_STATE();
    case 83:
      if (lookahead == 'a') ADVANCE(136);
      END_STATE();
    case 84:
      if (lookahead == 'a') ADVANCE(435);
      END_STATE();
    case 85:
      if (lookahead == 'a') ADVANCE(423);
      if (lookahead == 'o') ADVANCE(278);
      END_STATE();
    case 86:
      if (lookahead == 'a') ADVANCE(363);
      END_STATE();
    case 87:
      if (lookahead == 'a') ADVANCE(398);
      END_STATE();
    case 88:
      if (lookahead == 'a') ADVANCE(413);
      END_STATE();
    case 89:
      if (lookahead == 'a') ADVANCE(441);
      END_STATE();
    case 90:
      if (lookahead == 'a') ADVANCE(434);
      END_STATE();
    case 91:
      if (lookahead == 'a') ADVANCE(436);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(281);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(212);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(269);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(286);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(213);
      END_STATE();
    case 97:
      if (lookahead == 'a') ADVANCE(293);
      END_STATE();
    case 98:
      if (lookahead == 'b') ADVANCE(309);
      if (lookahead == 'c') ADVANCE(257);
      if (lookahead == 'e') ADVANCE(122);
      if (lookahead == 'h') ADVANCE(305);
      if (lookahead == 'r') ADVANCE(92);
      if (lookahead == 't') ADVANCE(218);
      if (lookahead == 'w') ADVANCE(73);
      END_STATE();
    case 99:
      if (lookahead == 'b') ADVANCE(309);
      if (lookahead == 'c') ADVANCE(257);
      if (lookahead == 'e') ADVANCE(122);
      if (lookahead == 'h') ADVANCE(305);
      if (lookahead == 't') ADVANCE(218);
      if (lookahead == 'w') ADVANCE(73);
      END_STATE();
    case 100:
      if (lookahead == 'b') ADVANCE(128);
      END_STATE();
    case 101:
      if (lookahead == 'b') ADVANCE(317);
      END_STATE();
    case 102:
      if (lookahead == 'b') ADVANCE(320);
      END_STATE();
    case 103:
      if (lookahead == 'c') ADVANCE(217);
      END_STATE();
    case 104:
      if (lookahead == 'c') ADVANCE(537);
      END_STATE();
    case 105:
      if (lookahead == 'c') ADVANCE(527);
      END_STATE();
    case 106:
      if (lookahead == 'c') ADVANCE(528);
      END_STATE();
    case 107:
      if (lookahead == 'c') ADVANCE(235);
      if (lookahead == 'l') ADVANCE(85);
      if (lookahead == 'm') ADVANCE(175);
      if (lookahead == 'p') ADVANCE(326);
      END_STATE();
    case 108:
      if (lookahead == 'c') ADVANCE(310);
      if (lookahead == 'h') ADVANCE(323);
      if (lookahead == 'r') ADVANCE(144);
      if (lookahead == 'u') ADVANCE(400);
      if (lookahead == 'x') ADVANCE(50);
      END_STATE();
    case 109:
      if (lookahead == 'c') ADVANCE(324);
      END_STATE();
    case 110:
      if (lookahead == 'c') ADVANCE(148);
      END_STATE();
    case 111:
      if (lookahead == 'c') ADVANCE(453);
      END_STATE();
    case 112:
      if (lookahead == 'c') ADVANCE(191);
      END_STATE();
    case 113:
      if (lookahead == 'c') ADVANCE(328);
      END_STATE();
    case 114:
      if (lookahead == 'c') ADVANCE(327);
      END_STATE();
    case 115:
      if (lookahead == 'c') ADVANCE(329);
      END_STATE();
    case 116:
      if (lookahead == 'c') ADVANCE(330);
      END_STATE();
    case 117:
      if (lookahead == 'c') ADVANCE(332);
      END_STATE();
    case 118:
      if (lookahead == 'c') ADVANCE(331);
      END_STATE();
    case 119:
      if (lookahead == 'c') ADVANCE(263);
      END_STATE();
    case 120:
      if (lookahead == 'c') ADVANCE(334);
      if (lookahead == 'f') ADVANCE(459);
      if (lookahead == 'm') ADVANCE(182);
      if (lookahead == 't') ADVANCE(247);
      if (lookahead == 'u') ADVANCE(367);
      if (lookahead == 'v') ADVANCE(180);
      END_STATE();
    case 121:
      if (lookahead == 'd') ADVANCE(485);
      END_STATE();
    case 122:
      if (lookahead == 'd') ADVANCE(211);
      END_STATE();
    case 123:
      if (lookahead == 'd') ADVANCE(567);
      END_STATE();
    case 124:
      if (lookahead == 'd') ADVANCE(543);
      END_STATE();
    case 125:
      if (lookahead == 'd') ADVANCE(573);
      END_STATE();
    case 126:
      if (lookahead == 'd') ADVANCE(574);
      END_STATE();
    case 127:
      if (lookahead == 'd') ADVANCE(571);
      END_STATE();
    case 128:
      if (lookahead == 'd') ADVANCE(228);
      END_STATE();
    case 129:
      if (lookahead == 'd') ADVANCE(303);
      END_STATE();
    case 130:
      if (lookahead == 'd') ADVANCE(63);
      END_STATE();
    case 131:
      if (lookahead == 'd') ADVANCE(162);
      END_STATE();
    case 132:
      if (lookahead == 'd') ADVANCE(149);
      END_STATE();
    case 133:
      if (lookahead == 'd') ADVANCE(150);
      END_STATE();
    case 134:
      if (lookahead == 'd') ADVANCE(153);
      END_STATE();
    case 135:
      if (lookahead == 'd') ADVANCE(154);
      END_STATE();
    case 136:
      if (lookahead == 'd') ADVANCE(89);
      END_STATE();
    case 137:
      if (lookahead == 'd') ADVANCE(187);
      END_STATE();
    case 138:
      if (lookahead == 'd') ADVANCE(64);
      END_STATE();
    case 139:
      if (lookahead == 'e') ADVANCE(498);
      if (lookahead == 't') ADVANCE(497);
      END_STATE();
    case 140:
      if (lookahead == 'e') ADVANCE(496);
      if (lookahead == 't') ADVANCE(495);
      END_STATE();
    case 141:
      if (lookahead == 'e') ADVANCE(494);
      if (lookahead == 'o') ADVANCE(419);
      END_STATE();
    case 142:
      if (lookahead == 'e') ADVANCE(513);
      END_STATE();
    case 143:
      if (lookahead == 'e') ADVANCE(514);
      END_STATE();
    case 144:
      if (lookahead == 'e') ADVANCE(203);
      END_STATE();
    case 145:
      if (lookahead == 'e') ADVANCE(539);
      END_STATE();
    case 146:
      if (lookahead == 'e') ADVANCE(533);
      END_STATE();
    case 147:
      if (lookahead == 'e') ADVANCE(532);
      END_STATE();
    case 148:
      if (lookahead == 'e') ADVANCE(536);
      END_STATE();
    case 149:
      if (lookahead == 'e') ADVANCE(555);
      END_STATE();
    case 150:
      if (lookahead == 'e') ADVANCE(554);
      END_STATE();
    case 151:
      if (lookahead == 'e') ADVANCE(530);
      END_STATE();
    case 152:
      if (lookahead == 'e') ADVANCE(566);
      END_STATE();
    case 153:
      if (lookahead == 'e') ADVANCE(558);
      END_STATE();
    case 154:
      if (lookahead == 'e') ADVANCE(559);
      END_STATE();
    case 155:
      if (lookahead == 'e') ADVANCE(350);
      END_STATE();
    case 156:
      if (lookahead == 'e') ADVANCE(471);
      END_STATE();
    case 157:
      if (lookahead == 'e') ADVANCE(306);
      END_STATE();
    case 158:
      if (lookahead == 'e') ADVANCE(387);
      END_STATE();
    case 159:
      if (lookahead == 'e') ADVANCE(123);
      END_STATE();
    case 160:
      if (lookahead == 'e') ADVANCE(36);
      END_STATE();
    case 161:
      if (lookahead == 'e') ADVANCE(370);
      END_STATE();
    case 162:
      if (lookahead == 'e') ADVANCE(138);
      END_STATE();
    case 163:
      if (lookahead == 'e') ADVANCE(462);
      END_STATE();
    case 164:
      if (lookahead == 'e') ADVANCE(111);
      END_STATE();
    case 165:
      if (lookahead == 'e') ADVANCE(365);
      END_STATE();
    case 166:
      if (lookahead == 'e') ADVANCE(105);
      END_STATE();
    case 167:
      if (lookahead == 'e') ADVANCE(106);
      END_STATE();
    case 168:
      if (lookahead == 'e') ADVANCE(355);
      END_STATE();
    case 169:
      if (lookahead == 'e') ADVANCE(130);
      END_STATE();
    case 170:
      if (lookahead == 'e') ADVANCE(125);
      END_STATE();
    case 171:
      if (lookahead == 'e') ADVANCE(34);
      END_STATE();
    case 172:
      if (lookahead == 'e') ADVANCE(94);
      END_STATE();
    case 173:
      if (lookahead == 'e') ADVANCE(356);
      END_STATE();
    case 174:
      if (lookahead == 'e') ADVANCE(126);
      END_STATE();
    case 175:
      if (lookahead == 'e') ADVANCE(439);
      END_STATE();
    case 176:
      if (lookahead == 'e') ADVANCE(390);
      END_STATE();
    case 177:
      if (lookahead == 'e') ADVANCE(127);
      END_STATE();
    case 178:
      if (lookahead == 'e') ADVANCE(368);
      END_STATE();
    case 179:
      if (lookahead == 'e') ADVANCE(97);
      END_STATE();
    case 180:
      if (lookahead == 'e') ADVANCE(372);
      END_STATE();
    case 181:
      if (lookahead == 'e') ADVANCE(438);
      END_STATE();
    case 182:
      if (lookahead == 'e') ADVANCE(430);
      END_STATE();
    case 183:
      if (lookahead == 'e') ADVANCE(375);
      END_STATE();
    case 184:
      if (lookahead == 'e') ADVANCE(159);
      END_STATE();
    case 185:
      if (lookahead == 'e') ADVANCE(361);
      END_STATE();
    case 186:
      if (lookahead == 'e') ADVANCE(362);
      END_STATE();
    case 187:
      if (lookahead == 'e') ADVANCE(447);
      END_STATE();
    case 188:
      if (lookahead == 'e') ADVANCE(287);
      END_STATE();
    case 189:
      if (lookahead == 'e') ADVANCE(84);
      END_STATE();
    case 190:
      if (lookahead == 'e') ADVANCE(377);
      END_STATE();
    case 191:
      if (lookahead == 'e') ADVANCE(383);
      END_STATE();
    case 192:
      if (lookahead == 'e') ADVANCE(290);
      END_STATE();
    case 193:
      if (lookahead == 'e') ADVANCE(275);
      END_STATE();
    case 194:
      if (lookahead == 'e') ADVANCE(410);
      END_STATE();
    case 195:
      if (lookahead == 'e') ADVANCE(295);
      END_STATE();
    case 196:
      if (lookahead == 'e') ADVANCE(299);
      END_STATE();
    case 197:
      if (lookahead == 'e') ADVANCE(412);
      END_STATE();
    case 198:
      if (lookahead == 'e') ADVANCE(296);
      END_STATE();
    case 199:
      if (lookahead == 'e') ADVANCE(407);
      END_STATE();
    case 200:
      if (lookahead == 'e') ADVANCE(386);
      END_STATE();
    case 201:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(283);
      END_STATE();
    case 202:
      if (lookahead == 'f') ADVANCE(28);
      END_STATE();
    case 203:
      if (lookahead == 'f') ADVANCE(190);
      if (lookahead == 'q') ADVANCE(461);
      END_STATE();
    case 204:
      if (lookahead == 'f') ADVANCE(19);
      END_STATE();
    case 205:
      if (lookahead == 'f') ADVANCE(312);
      END_STATE();
    case 206:
      if (lookahead == 'f') ADVANCE(242);
      END_STATE();
    case 207:
      if (lookahead == 'f') ADVANCE(319);
      END_STATE();
    case 208:
      if (lookahead == 'f') ADVANCE(243);
      END_STATE();
    case 209:
      if (lookahead == 'f') ADVANCE(469);
      if (lookahead == 'u') ADVANCE(371);
      END_STATE();
    case 210:
      if (lookahead == 'g') ADVANCE(157);
      if (lookahead == 's') ADVANCE(359);
      END_STATE();
    case 211:
      if (lookahead == 'g') ADVANCE(160);
      END_STATE();
    case 212:
      if (lookahead == 'g') ADVANCE(193);
      END_STATE();
    case 213:
      if (lookahead == 'g') ADVANCE(195);
      END_STATE();
    case 214:
      if (lookahead == 'h') ADVANCE(546);
      END_STATE();
    case 215:
      if (lookahead == 'h') ADVANCE(562);
      END_STATE();
    case 216:
      if (lookahead == 'h') ADVANCE(564);
      END_STATE();
    case 217:
      if (lookahead == 'h') ADVANCE(158);
      END_STATE();
    case 218:
      if (lookahead == 'h') ADVANCE(366);
      if (lookahead == 'l') ADVANCE(393);
      END_STATE();
    case 219:
      if (lookahead == 'h') ADVANCE(313);
      END_STATE();
    case 220:
      if (lookahead == 'h') ADVANCE(35);
      END_STATE();
    case 221:
      if (lookahead == 'h') ADVANCE(87);
      END_STATE();
    case 222:
      if (lookahead == 'h') ADVANCE(449);
      END_STATE();
    case 223:
      if (lookahead == 'i') ADVANCE(545);
      END_STATE();
    case 224:
      if (lookahead == 'i') ADVANCE(534);
      END_STATE();
    case 225:
      if (lookahead == 'i') ADVANCE(561);
      END_STATE();
    case 226:
      if (lookahead == 'i') ADVANCE(542);
      END_STATE();
    case 227:
      if (lookahead == 'i') ADVANCE(560);
      END_STATE();
    case 228:
      if (lookahead == 'i') ADVANCE(470);
      END_STATE();
    case 229:
      if (lookahead == 'i') ADVANCE(285);
      END_STATE();
    case 230:
      if (lookahead == 'i') ADVANCE(337);
      if (lookahead == 'p') ADVANCE(318);
      END_STATE();
    case 231:
      if (lookahead == 'i') ADVANCE(206);
      END_STATE();
    case 232:
      if (lookahead == 'i') ADVANCE(188);
      END_STATE();
    case 233:
      if (lookahead == 'i') ADVANCE(288);
      END_STATE();
    case 234:
      if (lookahead == 'i') ADVANCE(300);
      END_STATE();
    case 235:
      if (lookahead == 'i') ADVANCE(422);
      END_STATE();
    case 236:
      if (lookahead == 'i') ADVANCE(311);
      END_STATE();
    case 237:
      if (lookahead == 'i') ADVANCE(325);
      END_STATE();
    case 238:
      if (lookahead == 'i') ADVANCE(415);
      END_STATE();
    case 239:
      if (lookahead == 'i') ADVANCE(145);
      END_STATE();
    case 240:
      if (lookahead == 'i') ADVANCE(315);
      END_STATE();
    case 241:
      if (lookahead == 'i') ADVANCE(316);
      END_STATE();
    case 242:
      if (lookahead == 'i') ADVANCE(169);
      END_STATE();
    case 243:
      if (lookahead == 'i') ADVANCE(174);
      END_STATE();
    case 244:
      if (lookahead == 'i') ADVANCE(340);
      END_STATE();
    case 245:
      if (lookahead == 'i') ADVANCE(176);
      END_STATE();
    case 246:
      if (lookahead == 'i') ADVANCE(411);
      END_STATE();
    case 247:
      if (lookahead == 'i') ADVANCE(274);
      END_STATE();
    case 248:
      if (lookahead == 'i') ADVANCE(208);
      END_STATE();
    case 249:
      if (lookahead == 'i') ADVANCE(192);
      END_STATE();
    case 250:
      if (lookahead == 'i') ADVANCE(416);
      END_STATE();
    case 251:
      if (lookahead == 'j') ADVANCE(74);
      if (lookahead == 's') ADVANCE(117);
      if (lookahead == 'v') ADVANCE(183);
      END_STATE();
    case 252:
      if (lookahead == 'k') ADVANCE(161);
      END_STATE();
    case 253:
      if (lookahead == 'k') ADVANCE(170);
      END_STATE();
    case 254:
      if (lookahead == 'k') ADVANCE(239);
      END_STATE();
    case 255:
      if (lookahead == 'k') ADVANCE(245);
      END_STATE();
    case 256:
      if (lookahead == 'l') ADVANCE(569);
      END_STATE();
    case 257:
      if (lookahead == 'l') ADVANCE(232);
      END_STATE();
    case 258:
      if (lookahead == 'l') ADVANCE(392);
      END_STATE();
    case 259:
      if (lookahead == 'l') ADVANCE(261);
      END_STATE();
    case 260:
      if (lookahead == 'l') ADVANCE(224);
      END_STATE();
    case 261:
      if (lookahead == 'l') ADVANCE(58);
      END_STATE();
    case 262:
      if (lookahead == 'l') ADVANCE(60);
      END_STATE();
    case 263:
      if (lookahead == 'l') ADVANCE(249);
      END_STATE();
    case 264:
      if (lookahead == 'l') ADVANCE(262);
      END_STATE();
    case 265:
      if (lookahead == 'l') ADVANCE(66);
      END_STATE();
    case 266:
      if (lookahead == 'm') ADVANCE(529);
      END_STATE();
    case 267:
      if (lookahead == 'm') ADVANCE(61);
      END_STATE();
    case 268:
      if (lookahead == 'm') ADVANCE(95);
      END_STATE();
    case 269:
      if (lookahead == 'm') ADVANCE(47);
      END_STATE();
    case 270:
      if (lookahead == 'm') ADVANCE(171);
      END_STATE();
    case 271:
      if (lookahead == 'm') ADVANCE(181);
      END_STATE();
    case 272:
      if (lookahead == 'm') ADVANCE(342);
      END_STATE();
    case 273:
      if (lookahead == 'm') ADVANCE(408);
      if (lookahead == 's') ADVANCE(166);
      END_STATE();
    case 274:
      if (lookahead == 'm') ADVANCE(199);
      END_STATE();
    case 275:
      if (lookahead == 'm') ADVANCE(196);
      END_STATE();
    case 276:
      if (lookahead == 'n') ADVANCE(121);
      END_STATE();
    case 277:
      if (lookahead == 'n') ADVANCE(483);
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 278:
      if (lookahead == 'n') ADVANCE(552);
      END_STATE();
    case 279:
      if (lookahead == 'n') ADVANCE(549);
      END_STATE();
    case 280:
      if (lookahead == 'n') ADVANCE(568);
      END_STATE();
    case 281:
      if (lookahead == 'n') ADVANCE(129);
      END_STATE();
    case 282:
      if (lookahead == 'n') ADVANCE(458);
      END_STATE();
    case 283:
      if (lookahead == 'n') ADVANCE(433);
      END_STATE();
    case 284:
      if (lookahead == 'n') ADVANCE(78);
      END_STATE();
    case 285:
      if (lookahead == 'n') ADVANCE(388);
      END_STATE();
    case 286:
      if (lookahead == 'n') ADVANCE(93);
      END_STATE();
    case 287:
      if (lookahead == 'n') ADVANCE(437);
      END_STATE();
    case 288:
      if (lookahead == 'n') ADVANCE(56);
      END_STATE();
    case 289:
      if (lookahead == 'n') ADVANCE(48);
      END_STATE();
    case 290:
      if (lookahead == 'n') ADVANCE(450);
      END_STATE();
    case 291:
      if (lookahead == 'n') ADVANCE(452);
      if (lookahead == 'u') ADVANCE(294);
      END_STATE();
    case 292:
      if (lookahead == 'n') ADVANCE(27);
      END_STATE();
    case 293:
      if (lookahead == 'n') ADVANCE(54);
      END_STATE();
    case 294:
      if (lookahead == 'n') ADVANCE(445);
      END_STATE();
    case 295:
      if (lookahead == 'n') ADVANCE(425);
      END_STATE();
    case 296:
      if (lookahead == 'n') ADVANCE(426);
      END_STATE();
    case 297:
      if (lookahead == 'n') ADVANCE(152);
      END_STATE();
    case 298:
      if (lookahead == 'n') ADVANCE(240);
      END_STATE();
    case 299:
      if (lookahead == 'n') ADVANCE(444);
      END_STATE();
    case 300:
      if (lookahead == 'n') ADVANCE(198);
      END_STATE();
    case 301:
      if (lookahead == 'o') ADVANCE(291);
      END_STATE();
    case 302:
      if (lookahead == 'o') ADVANCE(254);
      END_STATE();
    case 303:
      if (lookahead == 'o') ADVANCE(267);
      END_STATE();
    case 304:
      if (lookahead == 'o') ADVANCE(353);
      END_STATE();
    case 305:
      if (lookahead == 'o') ADVANCE(396);
      END_STATE();
    case 306:
      if (lookahead == 'o') ADVANCE(244);
      END_STATE();
    case 307:
      if (lookahead == 'o') ADVANCE(419);
      END_STATE();
    case 308:
      if (lookahead == 'o') ADVANCE(344);
      END_STATE();
    case 309:
      if (lookahead == 'o') ADVANCE(420);
      END_STATE();
    case 310:
      if (lookahead == 'o') ADVANCE(302);
      END_STATE();
    case 311:
      if (lookahead == 'o') ADVANCE(279);
      END_STATE();
    case 312:
      if (lookahead == 'o') ADVANCE(358);
      END_STATE();
    case 313:
      if (lookahead == 'o') ADVANCE(124);
      END_STATE();
    case 314:
      if (lookahead == 'o') ADVANCE(297);
      END_STATE();
    case 315:
      if (lookahead == 'o') ADVANCE(280);
      END_STATE();
    case 316:
      if (lookahead == 'o') ADVANCE(292);
      END_STATE();
    case 317:
      if (lookahead == 'o') ADVANCE(424);
      END_STATE();
    case 318:
      if (lookahead == 'o') ADVANCE(381);
      END_STATE();
    case 319:
      if (lookahead == 'o') ADVANCE(357);
      END_STATE();
    case 320:
      if (lookahead == 'o') ADVANCE(428);
      END_STATE();
    case 321:
      if (lookahead == 'o') ADVANCE(253);
      END_STATE();
    case 322:
      if (lookahead == 'o') ADVANCE(52);
      END_STATE();
    case 323:
      if (lookahead == 'o') ADVANCE(399);
      END_STATE();
    case 324:
      if (lookahead == 'o') ADVANCE(132);
      END_STATE();
    case 325:
      if (lookahead == 'o') ADVANCE(289);
      END_STATE();
    case 326:
      if (lookahead == 'o') ADVANCE(404);
      END_STATE();
    case 327:
      if (lookahead == 'o') ADVANCE(133);
      END_STATE();
    case 328:
      if (lookahead == 'o') ADVANCE(379);
      END_STATE();
    case 329:
      if (lookahead == 'o') ADVANCE(380);
      END_STATE();
    case 330:
      if (lookahead == 'o') ADVANCE(134);
      END_STATE();
    case 331:
      if (lookahead == 'o') ADVANCE(135);
      END_STATE();
    case 332:
      if (lookahead == 'o') ADVANCE(384);
      END_STATE();
    case 333:
      if (lookahead == 'o') ADVANCE(255);
      END_STATE();
    case 334:
      if (lookahead == 'o') ADVANCE(333);
      END_STATE();
    case 335:
      if (lookahead == 'o') ADVANCE(68);
      END_STATE();
    case 336:
      if (lookahead == 'o') ADVANCE(69);
      END_STATE();
    case 337:
      if (lookahead == 'p') ADVANCE(538);
      END_STATE();
    case 338:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 339:
      if (lookahead == 'p') ADVANCE(7);
      END_STATE();
    case 340:
      if (lookahead == 'p') ADVANCE(8);
      END_STATE();
    case 341:
      if (lookahead == 'p') ADVANCE(37);
      END_STATE();
    case 342:
      if (lookahead == 'p') ADVANCE(13);
      END_STATE();
    case 343:
      if (lookahead == 'p') ADVANCE(88);
      END_STATE();
    case 344:
      if (lookahead == 'p') ADVANCE(179);
      END_STATE();
    case 345:
      if (lookahead == 'p') ADVANCE(90);
      if (lookahead == 'q') ADVANCE(466);
      END_STATE();
    case 346:
      if (lookahead == 'p') ADVANCE(91);
      if (lookahead == 'q') ADVANCE(467);
      END_STATE();
    case 347:
      if (lookahead == 'p') ADVANCE(405);
      END_STATE();
    case 348:
      if (lookahead == 'q') ADVANCE(493);
      END_STATE();
    case 349:
      if (lookahead == 'q') ADVANCE(260);
      END_STATE();
    case 350:
      if (lookahead == 'q') ADVANCE(468);
      END_STATE();
    case 351:
      if (lookahead == 'r') ADVANCE(488);
      END_STATE();
    case 352:
      if (lookahead == 'r') ADVANCE(455);
      END_STATE();
    case 353:
      if (lookahead == 'r') ADVANCE(486);
      END_STATE();
    case 354:
      if (lookahead == 'r') ADVANCE(252);
      END_STATE();
    case 355:
      if (lookahead == 'r') ADVANCE(472);
      END_STATE();
    case 356:
      if (lookahead == 'r') ADVANCE(541);
      END_STATE();
    case 357:
      if (lookahead == 'r') ADVANCE(550);
      END_STATE();
    case 358:
      if (lookahead == 'r') ADVANCE(474);
      END_STATE();
    case 359:
      if (lookahead == 'r') ADVANCE(104);
      END_STATE();
    case 360:
      if (lookahead == 'r') ADVANCE(476);
      END_STATE();
    case 361:
      if (lookahead == 'r') ADVANCE(477);
      END_STATE();
    case 362:
      if (lookahead == 'r') ADVANCE(478);
      END_STATE();
    case 363:
      if (lookahead == 'r') ADVANCE(131);
      END_STATE();
    case 364:
      if (lookahead == 'r') ADVANCE(110);
      if (lookahead == 's') ADVANCE(349);
      if (lookahead == 'x') ADVANCE(402);
      END_STATE();
    case 365:
      if (lookahead == 'r') ADVANCE(65);
      END_STATE();
    case 366:
      if (lookahead == 'r') ADVANCE(189);
      END_STATE();
    case 367:
      if (lookahead == 'r') ADVANCE(223);
      END_STATE();
    case 368:
      if (lookahead == 'r') ADVANCE(46);
      END_STATE();
    case 369:
      if (lookahead == 'r') ADVANCE(322);
      END_STATE();
    case 370:
      if (lookahead == 'r') ADVANCE(20);
      END_STATE();
    case 371:
      if (lookahead == 'r') ADVANCE(225);
      END_STATE();
    case 372:
      if (lookahead == 'r') ADVANCE(401);
      END_STATE();
    case 373:
      if (lookahead == 'r') ADVANCE(226);
      END_STATE();
    case 374:
      if (lookahead == 'r') ADVANCE(308);
      END_STATE();
    case 375:
      if (lookahead == 'r') ADVANCE(231);
      END_STATE();
    case 376:
      if (lookahead == 'r') ADVANCE(227);
      END_STATE();
    case 377:
      if (lookahead == 'r') ADVANCE(173);
      END_STATE();
    case 378:
      if (lookahead == 'r') ADVANCE(155);
      END_STATE();
    case 379:
      if (lookahead == 'r') ADVANCE(146);
      END_STATE();
    case 380:
      if (lookahead == 'r') ADVANCE(147);
      END_STATE();
    case 381:
      if (lookahead == 'r') ADVANCE(427);
      END_STATE();
    case 382:
      if (lookahead == 'r') ADVANCE(172);
      END_STATE();
    case 383:
      if (lookahead == 'r') ADVANCE(446);
      END_STATE();
    case 384:
      if (lookahead == 'r') ADVANCE(151);
      END_STATE();
    case 385:
      if (lookahead == 'r') ADVANCE(156);
      if (lookahead == 'v') ADVANCE(200);
      END_STATE();
    case 386:
      if (lookahead == 'r') ADVANCE(248);
      END_STATE();
    case 387:
      if (lookahead == 's') ADVANCE(506);
      END_STATE();
    case 388:
      if (lookahead == 's') ADVANCE(505);
      END_STATE();
    case 389:
      if (lookahead == 's') ADVANCE(535);
      END_STATE();
    case 390:
      if (lookahead == 's') ADVANCE(544);
      END_STATE();
    case 391:
      if (lookahead == 's') ADVANCE(256);
      END_STATE();
    case 392:
      if (lookahead == 's') ADVANCE(143);
      END_STATE();
    case 393:
      if (lookahead == 's') ADVANCE(51);
      END_STATE();
    case 394:
      if (lookahead == 's') ADVANCE(113);
      END_STATE();
    case 395:
      if (lookahead == 's') ADVANCE(282);
      END_STATE();
    case 396:
      if (lookahead == 's') ADVANCE(431);
      END_STATE();
    case 397:
      if (lookahead == 's') ADVANCE(57);
      END_STATE();
    case 398:
      if (lookahead == 's') ADVANCE(216);
      END_STATE();
    case 399:
      if (lookahead == 's') ADVANCE(421);
      END_STATE();
    case 400:
      if (lookahead == 's') ADVANCE(165);
      END_STATE();
    case 401:
      if (lookahead == 's') ADVANCE(236);
      END_STATE();
    case 402:
      if (lookahead == 's') ADVANCE(389);
      END_STATE();
    case 403:
      if (lookahead == 's') ADVANCE(168);
      END_STATE();
    case 404:
      if (lookahead == 's') ADVANCE(448);
      END_STATE();
    case 405:
      if (lookahead == 's') ADVANCE(454);
      END_STATE();
    case 406:
      if (lookahead == 's') ADVANCE(184);
      END_STATE();
    case 407:
      if (lookahead == 's') ADVANCE(443);
      END_STATE();
    case 408:
      if (lookahead == 's') ADVANCE(167);
      END_STATE();
    case 409:
      if (lookahead == 's') ADVANCE(177);
      END_STATE();
    case 410:
      if (lookahead == 's') ADVANCE(440);
      END_STATE();
    case 411:
      if (lookahead == 's') ADVANCE(237);
      END_STATE();
    case 412:
      if (lookahead == 's') ADVANCE(442);
      END_STATE();
    case 413:
      if (lookahead == 's') ADVANCE(409);
      END_STATE();
    case 414:
      if (lookahead == 's') ADVANCE(115);
      END_STATE();
    case 415:
      if (lookahead == 's') ADVANCE(335);
      END_STATE();
    case 416:
      if (lookahead == 's') ADVANCE(336);
      END_STATE();
    case 417:
      if (lookahead == 't') ADVANCE(339);
      END_STATE();
    case 418:
      if (lookahead == 't') ADVANCE(103);
      END_STATE();
    case 419:
      if (lookahead == 't') ADVANCE(524);
      END_STATE();
    case 420:
      if (lookahead == 't') ADVANCE(45);
      END_STATE();
    case 421:
      if (lookahead == 't') ADVANCE(540);
      END_STATE();
    case 422:
      if (lookahead == 't') ADVANCE(475);
      END_STATE();
    case 423:
      if (lookahead == 't') ADVANCE(551);
      END_STATE();
    case 424:
      if (lookahead == 't') ADVANCE(572);
      END_STATE();
    case 425:
      if (lookahead == 't') ADVANCE(548);
      END_STATE();
    case 426:
      if (lookahead == 't') ADVANCE(556);
      END_STATE();
    case 427:
      if (lookahead == 't') ADVANCE(531);
      END_STATE();
    case 428:
      if (lookahead == 't') ADVANCE(570);
      END_STATE();
    case 429:
      if (lookahead == 't') ADVANCE(417);
      END_STATE();
    case 430:
      if (lookahead == 't') ADVANCE(219);
      END_STATE();
    case 431:
      if (lookahead == 't') ADVANCE(284);
      END_STATE();
    case 432:
      if (lookahead == 't') ADVANCE(220);
      END_STATE();
    case 433:
      if (lookahead == 't') ADVANCE(76);
      END_STATE();
    case 434:
      if (lookahead == 't') ADVANCE(214);
      END_STATE();
    case 435:
      if (lookahead == 't') ADVANCE(67);
      END_STATE();
    case 436:
      if (lookahead == 't') ADVANCE(215);
      END_STATE();
    case 437:
      if (lookahead == 't') ADVANCE(9);
      END_STATE();
    case 438:
      if (lookahead == 't') ADVANCE(83);
      END_STATE();
    case 439:
      if (lookahead == 't') ADVANCE(369);
      END_STATE();
    case 440:
      if (lookahead == 't') ADVANCE(10);
      END_STATE();
    case 441:
      if (lookahead == 't') ADVANCE(75);
      END_STATE();
    case 442:
      if (lookahead == 't') ADVANCE(11);
      END_STATE();
    case 443:
      if (lookahead == 't') ADVANCE(80);
      END_STATE();
    case 444:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 445:
      if (lookahead == 't') ADVANCE(360);
      END_STATE();
    case 446:
      if (lookahead == 't') ADVANCE(49);
      END_STATE();
    case 447:
      if (lookahead == 't') ADVANCE(164);
      END_STATE();
    case 448:
      if (lookahead == 't') ADVANCE(79);
      END_STATE();
    case 449:
      if (lookahead == 't') ADVANCE(451);
      END_STATE();
    case 450:
      if (lookahead == 't') ADVANCE(55);
      END_STATE();
    case 451:
      if (lookahead == 't') ADVANCE(341);
      END_STATE();
    case 452:
      if (lookahead == 't') ADVANCE(234);
      END_STATE();
    case 453:
      if (lookahead == 't') ADVANCE(241);
      END_STATE();
    case 454:
      if (lookahead == 't') ADVANCE(382);
      END_STATE();
    case 455:
      if (lookahead == 'u') ADVANCE(142);
      END_STATE();
    case 456:
      if (lookahead == 'u') ADVANCE(347);
      END_STATE();
    case 457:
      if (lookahead == 'u') ADVANCE(100);
      END_STATE();
    case 458:
      if (lookahead == 'u') ADVANCE(266);
      END_STATE();
    case 459:
      if (lookahead == 'u') ADVANCE(259);
      END_STATE();
    case 460:
      if (lookahead == 'u') ADVANCE(298);
      END_STATE();
    case 461:
      if (lookahead == 'u') ADVANCE(194);
      END_STATE();
    case 462:
      if (lookahead == 'u') ADVANCE(374);
      END_STATE();
    case 463:
      if (lookahead == 'u') ADVANCE(373);
      END_STATE();
    case 464:
      if (lookahead == 'u') ADVANCE(432);
      END_STATE();
    case 465:
      if (lookahead == 'u') ADVANCE(376);
      END_STATE();
    case 466:
      if (lookahead == 'u') ADVANCE(185);
      END_STATE();
    case 467:
      if (lookahead == 'u') ADVANCE(186);
      END_STATE();
    case 468:
      if (lookahead == 'u') ADVANCE(197);
      END_STATE();
    case 469:
      if (lookahead == 'u') ADVANCE(264);
      END_STATE();
    case 470:
      if (lookahead == 'v') ADVANCE(246);
      END_STATE();
    case 471:
      if (lookahead == 'v') ADVANCE(321);
      END_STATE();
    case 472:
      if (lookahead == 'v') ADVANCE(178);
      END_STATE();
    case 473:
      if (lookahead == 'w') ADVANCE(21);
      END_STATE();
    case 474:
      if (lookahead == 'w') ADVANCE(86);
      END_STATE();
    case 475:
      if (lookahead == 'y') ADVANCE(553);
      END_STATE();
    case 476:
      if (lookahead == 'y') ADVANCE(557);
      END_STATE();
    case 477:
      if (lookahead == 'y') ADVANCE(547);
      END_STATE();
    case 478:
      if (lookahead == 'y') ADVANCE(563);
      END_STATE();
    case 479:
      if (lookahead == 'z') ADVANCE(314);
      END_STATE();
    case 480:
      if (lookahead == '|') ADVANCE(489);
      END_STATE();
    case 481:
      if (eof) ADVANCE(482);
      if (lookahead == '!') ADVANCE(525);
      if (lookahead == '#') ADVANCE(492);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(508);
      if (lookahead == ')') ADVANCE(509);
      if (lookahead == '/') ADVANCE(520);
      if (lookahead == '2') ADVANCE(15);
      if (lookahead == '^') ADVANCE(44);
      if (lookahead == 'a') ADVANCE(276);
      if (lookahead == 'c') ADVANCE(204);
      if (lookahead == 'h') ADVANCE(429);
      if (lookahead == 'i') ADVANCE(338);
      if (lookahead == 'n') ADVANCE(307);
      if (lookahead == 'o') ADVANCE(351);
      if (lookahead == 'r') ADVANCE(72);
      if (lookahead == 's') ADVANCE(391);
      if (lookahead == 'x') ADVANCE(304);
      if (lookahead == '|') ADVANCE(480);
      if (lookahead == '}') ADVANCE(491);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(17);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(481)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(18);
      END_STATE();
    case 482:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 483:
      ACCEPT_TOKEN(anon_sym_in);
      END_STATE();
    case 484:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 485:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 486:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 487:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 488:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 489:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 490:
      ACCEPT_TOKEN(anon_sym_LBRACE);
      END_STATE();
    case 491:
      ACCEPT_TOKEN(anon_sym_RBRACE);
      END_STATE();
    case 492:
      ACCEPT_TOKEN(sym_comment);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(492);
      END_STATE();
    case 493:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 494:
      ACCEPT_TOKEN(anon_sym_ne);
      END_STATE();
    case 495:
      ACCEPT_TOKEN(anon_sym_lt);
      END_STATE();
    case 496:
      ACCEPT_TOKEN(anon_sym_le);
      END_STATE();
    case 497:
      ACCEPT_TOKEN(anon_sym_gt);
      END_STATE();
    case 498:
      ACCEPT_TOKEN(anon_sym_ge);
      END_STATE();
    case 499:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 500:
      ACCEPT_TOKEN(anon_sym_BANG_EQ);
      END_STATE();
    case 501:
      ACCEPT_TOKEN(anon_sym_LT);
      if (lookahead == '=') ADVANCE(502);
      END_STATE();
    case 502:
      ACCEPT_TOKEN(anon_sym_LT_EQ);
      END_STATE();
    case 503:
      ACCEPT_TOKEN(anon_sym_GT);
      if (lookahead == '=') ADVANCE(504);
      END_STATE();
    case 504:
      ACCEPT_TOKEN(anon_sym_GT_EQ);
      END_STATE();
    case 505:
      ACCEPT_TOKEN(anon_sym_contains);
      END_STATE();
    case 506:
      ACCEPT_TOKEN(anon_sym_matches);
      END_STATE();
    case 507:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 508:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 509:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 510:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(511);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(511);
      END_STATE();
    case 511:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(511);
      END_STATE();
    case 512:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 513:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 514:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 515:
      ACCEPT_TOKEN(sym_ipv4);
      END_STATE();
    case 516:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '5') ADVANCE(517);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(515);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(518);
      END_STATE();
    case 517:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(515);
      END_STATE();
    case 518:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(515);
      END_STATE();
    case 519:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(518);
      END_STATE();
    case 520:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 521:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      END_STATE();
    case 522:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(521);
      END_STATE();
    case 523:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(521);
      END_STATE();
    case 524:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 525:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 526:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(500);
      END_STATE();
    case 527:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 528:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 529:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 530:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 531:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 532:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 533:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(364);
      END_STATE();
    case 534:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 535:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 536:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 537:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(107);
      END_STATE();
    case 538:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 539:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 540:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 541:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 542:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 543:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 544:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 545:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(345);
      END_STATE();
    case 546:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 547:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 548:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 549:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 550:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 551:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 552:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 553:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 554:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 555:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 556:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 557:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 558:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 559:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 560:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 561:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(346);
      END_STATE();
    case 562:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 563:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 564:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 565:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 566:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 567:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 568:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 569:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 570:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 571:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 572:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 573:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 574:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_verified);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 0},
  [2] = {.lex_state = 0},
  [3] = {.lex_state = 0},
  [4] = {.lex_state = 0},
  [5] = {.lex_state = 0},
  [6] = {.lex_state = 0},
  [7] = {.lex_state = 481},
  [8] = {.lex_state = 0},
  [9] = {.lex_state = 0},
  [10] = {.lex_state = 0},
  [11] = {.lex_state = 0},
  [12] = {.lex_state = 481},
  [13] = {.lex_state = 0},
  [14] = {.lex_state = 0},
  [15] = {.lex_state = 0},
  [16] = {.lex_state = 0},
  [17] = {.lex_state = 0},
  [18] = {.lex_state = 0},
  [19] = {.lex_state = 0},
  [20] = {.lex_state = 0},
  [21] = {.lex_state = 0},
  [22] = {.lex_state = 0},
  [23] = {.lex_state = 0},
  [24] = {.lex_state = 0},
  [25] = {.lex_state = 0},
  [26] = {.lex_state = 0},
  [27] = {.lex_state = 0},
  [28] = {.lex_state = 0},
  [29] = {.lex_state = 0},
  [30] = {.lex_state = 0},
  [31] = {.lex_state = 0},
  [32] = {.lex_state = 481},
  [33] = {.lex_state = 0},
  [34] = {.lex_state = 481},
  [35] = {.lex_state = 481},
  [36] = {.lex_state = 481},
  [37] = {.lex_state = 3},
  [38] = {.lex_state = 0},
  [39] = {.lex_state = 3},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 3},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 3},
  [48] = {.lex_state = 0},
  [49] = {.lex_state = 2},
  [50] = {.lex_state = 0},
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
    [anon_sym_LPAREN] = ACTIONS(1),
    [anon_sym_RPAREN] = ACTIONS(1),
    [sym_number] = ACTIONS(1),
    [sym_string] = ACTIONS(1),
    [anon_sym_true] = ACTIONS(1),
    [anon_sym_false] = ACTIONS(1),
    [anon_sym_SLASH] = ACTIONS(1),
    [aux_sym_ip_range_token1] = ACTIONS(1),
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
    [sym_source_file] = STATE(50),
    [sym__expression] = STATE(24),
    [sym_not_expression] = STATE(24),
    [sym_in_expression] = STATE(24),
    [sym_compound_expression] = STATE(24),
    [sym_simple_expression] = STATE(24),
    [sym_group] = STATE(24),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(5),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_not] = ACTIONS(9),
    [anon_sym_BANG] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(11),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(11),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(11),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(11),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(13),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(11),
    [anon_sym_ip_DOTsrc] = ACTIONS(15),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(17),
    [anon_sym_http_DOTcookie] = ACTIONS(19),
    [anon_sym_http_DOThost] = ACTIONS(19),
    [anon_sym_http_DOTreferer] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_http_DOTuser_agent] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(19),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(19),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(19),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(23),
    [anon_sym_ssl] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(23),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(23),
  },
  [2] = {
    [sym__expression] = STATE(24),
    [sym_not_expression] = STATE(24),
    [sym_in_expression] = STATE(24),
    [sym_compound_expression] = STATE(24),
    [sym_simple_expression] = STATE(24),
    [sym_group] = STATE(24),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(25),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(27),
    [anon_sym_not] = ACTIONS(30),
    [anon_sym_BANG] = ACTIONS(30),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(36),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(39),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(42),
    [anon_sym_http_DOTcookie] = ACTIONS(45),
    [anon_sym_http_DOThost] = ACTIONS(45),
    [anon_sym_http_DOTreferer] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(48),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(48),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(45),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(45),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(45),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(45),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(45),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(51),
    [anon_sym_ssl] = ACTIONS(51),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(51),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(51),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(51),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(51),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(51),
  },
  [3] = {
    [sym__expression] = STATE(24),
    [sym_not_expression] = STATE(24),
    [sym_in_expression] = STATE(24),
    [sym_compound_expression] = STATE(24),
    [sym_simple_expression] = STATE(24),
    [sym_group] = STATE(24),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(54),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_not] = ACTIONS(9),
    [anon_sym_BANG] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(11),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(11),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(11),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(11),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(13),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(11),
    [anon_sym_ip_DOTsrc] = ACTIONS(15),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(17),
    [anon_sym_http_DOTcookie] = ACTIONS(19),
    [anon_sym_http_DOThost] = ACTIONS(19),
    [anon_sym_http_DOTreferer] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_http_DOTuser_agent] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(19),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(19),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(19),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(23),
    [anon_sym_ssl] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(23),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(23),
  },
  [4] = {
    [ts_builtin_sym_end] = ACTIONS(56),
    [anon_sym_AMP_AMP] = ACTIONS(56),
    [anon_sym_and] = ACTIONS(56),
    [anon_sym_xor] = ACTIONS(56),
    [anon_sym_CARET_CARET] = ACTIONS(56),
    [anon_sym_or] = ACTIONS(56),
    [anon_sym_PIPE_PIPE] = ACTIONS(56),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(58),
    [anon_sym_ne] = ACTIONS(58),
    [anon_sym_EQ_EQ] = ACTIONS(58),
    [anon_sym_BANG_EQ] = ACTIONS(58),
    [anon_sym_LPAREN] = ACTIONS(56),
    [anon_sym_RPAREN] = ACTIONS(56),
    [anon_sym_not] = ACTIONS(56),
    [anon_sym_BANG] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(56),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(56),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(56),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(56),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(56),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(56),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(60),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(56),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(56),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(56),
    [anon_sym_ip_DOTsrc] = ACTIONS(60),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(56),
    [anon_sym_http_DOTcookie] = ACTIONS(56),
    [anon_sym_http_DOThost] = ACTIONS(56),
    [anon_sym_http_DOTreferer] = ACTIONS(56),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(56),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(56),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(56),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(56),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(56),
    [anon_sym_http_DOTuser_agent] = ACTIONS(56),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(56),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(56),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(56),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(56),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(56),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(56),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(56),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(56),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(56),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(56),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(56),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(56),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(60),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(56),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(56),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(56),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(56),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(56),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(56),
    [anon_sym_ssl] = ACTIONS(56),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(56),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(56),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(56),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(56),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(56),
  },
  [5] = {
    [ts_builtin_sym_end] = ACTIONS(62),
    [anon_sym_AMP_AMP] = ACTIONS(62),
    [anon_sym_and] = ACTIONS(62),
    [anon_sym_xor] = ACTIONS(62),
    [anon_sym_CARET_CARET] = ACTIONS(62),
    [anon_sym_or] = ACTIONS(62),
    [anon_sym_PIPE_PIPE] = ACTIONS(62),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(62),
    [anon_sym_ne] = ACTIONS(62),
    [anon_sym_EQ_EQ] = ACTIONS(62),
    [anon_sym_BANG_EQ] = ACTIONS(62),
    [anon_sym_LPAREN] = ACTIONS(62),
    [anon_sym_RPAREN] = ACTIONS(62),
    [anon_sym_not] = ACTIONS(62),
    [anon_sym_BANG] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(62),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(62),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(62),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(62),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(62),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(64),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(62),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(62),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(62),
    [anon_sym_ip_DOTsrc] = ACTIONS(64),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(62),
    [anon_sym_http_DOTcookie] = ACTIONS(62),
    [anon_sym_http_DOThost] = ACTIONS(62),
    [anon_sym_http_DOTreferer] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(62),
    [anon_sym_http_DOTuser_agent] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(62),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(62),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(62),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(62),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(62),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(62),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(62),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(62),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(62),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(62),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(62),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(62),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(64),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(62),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(62),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(62),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(62),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(62),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(62),
    [anon_sym_ssl] = ACTIONS(62),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(62),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(62),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(62),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(62),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(62),
  },
  [6] = {
    [sym__expression] = STATE(30),
    [sym_not_expression] = STATE(30),
    [sym_in_expression] = STATE(30),
    [sym_compound_expression] = STATE(30),
    [sym_simple_expression] = STATE(30),
    [sym_group] = STATE(30),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_not] = ACTIONS(9),
    [anon_sym_BANG] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(11),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(11),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(11),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(11),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(13),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(11),
    [anon_sym_ip_DOTsrc] = ACTIONS(15),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(17),
    [anon_sym_http_DOTcookie] = ACTIONS(19),
    [anon_sym_http_DOThost] = ACTIONS(19),
    [anon_sym_http_DOTreferer] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_http_DOTuser_agent] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(19),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(19),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(19),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(23),
    [anon_sym_ssl] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(23),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(23),
  },
  [7] = {
    [ts_builtin_sym_end] = ACTIONS(66),
    [anon_sym_AMP_AMP] = ACTIONS(66),
    [anon_sym_and] = ACTIONS(66),
    [anon_sym_xor] = ACTIONS(66),
    [anon_sym_CARET_CARET] = ACTIONS(66),
    [anon_sym_or] = ACTIONS(66),
    [anon_sym_PIPE_PIPE] = ACTIONS(66),
    [anon_sym_RBRACE] = ACTIONS(66),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(66),
    [anon_sym_RPAREN] = ACTIONS(66),
    [sym_ipv4] = ACTIONS(66),
    [anon_sym_SLASH] = ACTIONS(68),
    [anon_sym_not] = ACTIONS(66),
    [anon_sym_BANG] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(66),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(66),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(66),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(66),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(66),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(70),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(66),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(66),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(66),
    [anon_sym_ip_DOTsrc] = ACTIONS(70),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(66),
    [anon_sym_http_DOTcookie] = ACTIONS(66),
    [anon_sym_http_DOThost] = ACTIONS(66),
    [anon_sym_http_DOTreferer] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(70),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(66),
    [anon_sym_http_DOTuser_agent] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(66),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(66),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(66),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(66),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(66),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(66),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(66),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(66),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(66),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(66),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(66),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(66),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(70),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(66),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(66),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(66),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(66),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(66),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(66),
    [anon_sym_ssl] = ACTIONS(66),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(66),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(66),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(66),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(66),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(66),
  },
  [8] = {
    [sym__expression] = STATE(21),
    [sym_not_expression] = STATE(21),
    [sym_in_expression] = STATE(21),
    [sym_compound_expression] = STATE(21),
    [sym_simple_expression] = STATE(21),
    [sym_group] = STATE(21),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_not] = ACTIONS(9),
    [anon_sym_BANG] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(11),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(11),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(11),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(11),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(13),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(11),
    [anon_sym_ip_DOTsrc] = ACTIONS(15),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(17),
    [anon_sym_http_DOTcookie] = ACTIONS(19),
    [anon_sym_http_DOThost] = ACTIONS(19),
    [anon_sym_http_DOTreferer] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_http_DOTuser_agent] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(19),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(19),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(19),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(23),
    [anon_sym_ssl] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(23),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(23),
  },
  [9] = {
    [sym__expression] = STATE(22),
    [sym_not_expression] = STATE(22),
    [sym_in_expression] = STATE(22),
    [sym_compound_expression] = STATE(22),
    [sym_simple_expression] = STATE(22),
    [sym_group] = STATE(22),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_not] = ACTIONS(9),
    [anon_sym_BANG] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(11),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(11),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(11),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(11),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(13),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(11),
    [anon_sym_ip_DOTsrc] = ACTIONS(15),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(17),
    [anon_sym_http_DOTcookie] = ACTIONS(19),
    [anon_sym_http_DOThost] = ACTIONS(19),
    [anon_sym_http_DOTreferer] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_http_DOTuser_agent] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(19),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(19),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(19),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(23),
    [anon_sym_ssl] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(23),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(23),
  },
  [10] = {
    [sym__expression] = STATE(13),
    [sym_not_expression] = STATE(13),
    [sym_in_expression] = STATE(13),
    [sym_compound_expression] = STATE(13),
    [sym_simple_expression] = STATE(13),
    [sym_group] = STATE(13),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_not] = ACTIONS(9),
    [anon_sym_BANG] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(11),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(11),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(11),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(11),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(13),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(11),
    [anon_sym_ip_DOTsrc] = ACTIONS(15),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(17),
    [anon_sym_http_DOTcookie] = ACTIONS(19),
    [anon_sym_http_DOThost] = ACTIONS(19),
    [anon_sym_http_DOTreferer] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_http_DOTuser_agent] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(19),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(19),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(19),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(23),
    [anon_sym_ssl] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(23),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(23),
  },
  [11] = {
    [sym__expression] = STATE(23),
    [sym_not_expression] = STATE(23),
    [sym_in_expression] = STATE(23),
    [sym_compound_expression] = STATE(23),
    [sym_simple_expression] = STATE(23),
    [sym_group] = STATE(23),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(28),
    [sym_ip_field] = STATE(33),
    [sym_string_field] = STATE(27),
    [sym_boolean_field] = STATE(4),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(7),
    [anon_sym_not] = ACTIONS(9),
    [anon_sym_BANG] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(11),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(11),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(11),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(11),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(13),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(11),
    [anon_sym_ip_DOTsrc] = ACTIONS(15),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(17),
    [anon_sym_http_DOTcookie] = ACTIONS(19),
    [anon_sym_http_DOThost] = ACTIONS(19),
    [anon_sym_http_DOTreferer] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_http_DOTuser_agent] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(19),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(19),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(21),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(19),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(19),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(19),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(19),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(23),
    [anon_sym_ssl] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(23),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(23),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(23),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(23),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(72),
    [anon_sym_AMP_AMP] = ACTIONS(72),
    [anon_sym_and] = ACTIONS(72),
    [anon_sym_xor] = ACTIONS(72),
    [anon_sym_CARET_CARET] = ACTIONS(72),
    [anon_sym_or] = ACTIONS(72),
    [anon_sym_PIPE_PIPE] = ACTIONS(72),
    [anon_sym_RBRACE] = ACTIONS(72),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(72),
    [anon_sym_RPAREN] = ACTIONS(72),
    [sym_ipv4] = ACTIONS(72),
    [anon_sym_not] = ACTIONS(72),
    [anon_sym_BANG] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(72),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(72),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(72),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(72),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(72),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(74),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(72),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(72),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(72),
    [anon_sym_ip_DOTsrc] = ACTIONS(74),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(72),
    [anon_sym_http_DOTcookie] = ACTIONS(72),
    [anon_sym_http_DOThost] = ACTIONS(72),
    [anon_sym_http_DOTreferer] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(72),
    [anon_sym_http_DOTuser_agent] = ACTIONS(72),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(72),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(72),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(72),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(72),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(72),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(72),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(72),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(72),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(72),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(72),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(72),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(72),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(72),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(72),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(72),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(72),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(72),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(72),
    [anon_sym_ssl] = ACTIONS(72),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(72),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(72),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(72),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(72),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(72),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(76),
    [anon_sym_AMP_AMP] = ACTIONS(76),
    [anon_sym_and] = ACTIONS(76),
    [anon_sym_xor] = ACTIONS(76),
    [anon_sym_CARET_CARET] = ACTIONS(76),
    [anon_sym_or] = ACTIONS(76),
    [anon_sym_PIPE_PIPE] = ACTIONS(76),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(76),
    [anon_sym_RPAREN] = ACTIONS(76),
    [anon_sym_not] = ACTIONS(76),
    [anon_sym_BANG] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(76),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(76),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(76),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(76),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(76),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(78),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(76),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(76),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(76),
    [anon_sym_ip_DOTsrc] = ACTIONS(78),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(76),
    [anon_sym_http_DOTcookie] = ACTIONS(76),
    [anon_sym_http_DOThost] = ACTIONS(76),
    [anon_sym_http_DOTreferer] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(78),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(76),
    [anon_sym_http_DOTuser_agent] = ACTIONS(76),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(76),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(76),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(76),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(76),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(76),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(76),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(76),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(76),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(76),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(76),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(76),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(76),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(78),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(76),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(76),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(76),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(76),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(76),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(76),
    [anon_sym_ssl] = ACTIONS(76),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(76),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(76),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(76),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(76),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(76),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(80),
    [anon_sym_AMP_AMP] = ACTIONS(80),
    [anon_sym_and] = ACTIONS(80),
    [anon_sym_xor] = ACTIONS(80),
    [anon_sym_CARET_CARET] = ACTIONS(80),
    [anon_sym_or] = ACTIONS(80),
    [anon_sym_PIPE_PIPE] = ACTIONS(80),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(80),
    [anon_sym_RPAREN] = ACTIONS(80),
    [anon_sym_not] = ACTIONS(80),
    [anon_sym_BANG] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(80),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(80),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(80),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(80),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(80),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(82),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(80),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(80),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(80),
    [anon_sym_ip_DOTsrc] = ACTIONS(82),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(80),
    [anon_sym_http_DOTcookie] = ACTIONS(80),
    [anon_sym_http_DOThost] = ACTIONS(80),
    [anon_sym_http_DOTreferer] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(82),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(80),
    [anon_sym_http_DOTuser_agent] = ACTIONS(80),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(80),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(80),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(80),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(80),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(80),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(80),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(80),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(80),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(80),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(80),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(80),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(80),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(82),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(80),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(80),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(80),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(80),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(80),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(80),
    [anon_sym_ssl] = ACTIONS(80),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(80),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(80),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(80),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(80),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(80),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(84),
    [anon_sym_AMP_AMP] = ACTIONS(84),
    [anon_sym_and] = ACTIONS(84),
    [anon_sym_xor] = ACTIONS(84),
    [anon_sym_CARET_CARET] = ACTIONS(84),
    [anon_sym_or] = ACTIONS(84),
    [anon_sym_PIPE_PIPE] = ACTIONS(84),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(84),
    [anon_sym_RPAREN] = ACTIONS(84),
    [anon_sym_not] = ACTIONS(84),
    [anon_sym_BANG] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(84),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(84),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(84),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(84),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(84),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(86),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(84),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(84),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(84),
    [anon_sym_ip_DOTsrc] = ACTIONS(86),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(84),
    [anon_sym_http_DOTcookie] = ACTIONS(84),
    [anon_sym_http_DOThost] = ACTIONS(84),
    [anon_sym_http_DOTreferer] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(86),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(84),
    [anon_sym_http_DOTuser_agent] = ACTIONS(84),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(84),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(84),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(84),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(84),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(84),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(84),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(84),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(84),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(84),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(84),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(84),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(84),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(86),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(84),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(84),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(84),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(84),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(84),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(84),
    [anon_sym_ssl] = ACTIONS(84),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(84),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(84),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(84),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(84),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(84),
  },
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(88),
    [anon_sym_AMP_AMP] = ACTIONS(88),
    [anon_sym_and] = ACTIONS(88),
    [anon_sym_xor] = ACTIONS(88),
    [anon_sym_CARET_CARET] = ACTIONS(88),
    [anon_sym_or] = ACTIONS(88),
    [anon_sym_PIPE_PIPE] = ACTIONS(88),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(88),
    [anon_sym_RPAREN] = ACTIONS(88),
    [anon_sym_not] = ACTIONS(88),
    [anon_sym_BANG] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(88),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(88),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(88),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(88),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(88),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(90),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(88),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(88),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(88),
    [anon_sym_ip_DOTsrc] = ACTIONS(90),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(88),
    [anon_sym_http_DOTcookie] = ACTIONS(88),
    [anon_sym_http_DOThost] = ACTIONS(88),
    [anon_sym_http_DOTreferer] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(90),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(88),
    [anon_sym_http_DOTuser_agent] = ACTIONS(88),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(88),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(88),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(88),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(88),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(88),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(88),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(88),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(88),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(88),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(88),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(88),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(88),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(90),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(88),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(88),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(88),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(88),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(88),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(88),
    [anon_sym_ssl] = ACTIONS(88),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(88),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(88),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(88),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(88),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(88),
  },
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(92),
    [anon_sym_AMP_AMP] = ACTIONS(92),
    [anon_sym_and] = ACTIONS(92),
    [anon_sym_xor] = ACTIONS(92),
    [anon_sym_CARET_CARET] = ACTIONS(92),
    [anon_sym_or] = ACTIONS(92),
    [anon_sym_PIPE_PIPE] = ACTIONS(92),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(92),
    [anon_sym_RPAREN] = ACTIONS(92),
    [anon_sym_not] = ACTIONS(92),
    [anon_sym_BANG] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(92),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(92),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(92),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(92),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(92),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(94),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(92),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(92),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(92),
    [anon_sym_ip_DOTsrc] = ACTIONS(94),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(92),
    [anon_sym_http_DOTcookie] = ACTIONS(92),
    [anon_sym_http_DOThost] = ACTIONS(92),
    [anon_sym_http_DOTreferer] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(94),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(92),
    [anon_sym_http_DOTuser_agent] = ACTIONS(92),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(92),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(92),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(92),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(92),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(92),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(92),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(92),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(92),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(92),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(92),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(92),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(92),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(94),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(92),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(92),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(92),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(92),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(92),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(92),
    [anon_sym_ssl] = ACTIONS(92),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(92),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(92),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(92),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(92),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(92),
  },
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(96),
    [anon_sym_AMP_AMP] = ACTIONS(96),
    [anon_sym_and] = ACTIONS(96),
    [anon_sym_xor] = ACTIONS(96),
    [anon_sym_CARET_CARET] = ACTIONS(96),
    [anon_sym_or] = ACTIONS(96),
    [anon_sym_PIPE_PIPE] = ACTIONS(96),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(96),
    [anon_sym_RPAREN] = ACTIONS(96),
    [anon_sym_not] = ACTIONS(96),
    [anon_sym_BANG] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(96),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(96),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(96),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(98),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(96),
    [anon_sym_ip_DOTsrc] = ACTIONS(98),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(96),
    [anon_sym_http_DOTcookie] = ACTIONS(96),
    [anon_sym_http_DOThost] = ACTIONS(96),
    [anon_sym_http_DOTreferer] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(98),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(96),
    [anon_sym_http_DOTuser_agent] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(96),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(96),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(96),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(96),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(96),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(96),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(96),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(96),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(98),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(96),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(96),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(96),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(96),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(96),
    [anon_sym_ssl] = ACTIONS(96),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(96),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(96),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(96),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(96),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(96),
  },
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(100),
    [anon_sym_AMP_AMP] = ACTIONS(100),
    [anon_sym_and] = ACTIONS(100),
    [anon_sym_xor] = ACTIONS(100),
    [anon_sym_CARET_CARET] = ACTIONS(100),
    [anon_sym_or] = ACTIONS(100),
    [anon_sym_PIPE_PIPE] = ACTIONS(100),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(100),
    [anon_sym_RPAREN] = ACTIONS(100),
    [anon_sym_not] = ACTIONS(100),
    [anon_sym_BANG] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(100),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(100),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(100),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(100),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(100),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(102),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(100),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(100),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(100),
    [anon_sym_ip_DOTsrc] = ACTIONS(102),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(100),
    [anon_sym_http_DOTcookie] = ACTIONS(100),
    [anon_sym_http_DOThost] = ACTIONS(100),
    [anon_sym_http_DOTreferer] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(102),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(100),
    [anon_sym_http_DOTuser_agent] = ACTIONS(100),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(100),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(100),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(100),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(100),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(100),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(100),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(100),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(100),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(100),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(100),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(100),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(100),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(102),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(100),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(100),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(100),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(100),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(100),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(100),
    [anon_sym_ssl] = ACTIONS(100),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(100),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(100),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(100),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(100),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(100),
  },
  [20] = {
    [ts_builtin_sym_end] = ACTIONS(104),
    [anon_sym_AMP_AMP] = ACTIONS(104),
    [anon_sym_and] = ACTIONS(104),
    [anon_sym_xor] = ACTIONS(104),
    [anon_sym_CARET_CARET] = ACTIONS(104),
    [anon_sym_or] = ACTIONS(104),
    [anon_sym_PIPE_PIPE] = ACTIONS(104),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(104),
    [anon_sym_RPAREN] = ACTIONS(104),
    [anon_sym_not] = ACTIONS(104),
    [anon_sym_BANG] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(104),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(104),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(104),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(106),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(104),
    [anon_sym_ip_DOTsrc] = ACTIONS(106),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(104),
    [anon_sym_http_DOTcookie] = ACTIONS(104),
    [anon_sym_http_DOThost] = ACTIONS(104),
    [anon_sym_http_DOTreferer] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(106),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(104),
    [anon_sym_http_DOTuser_agent] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(104),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(104),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(104),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(104),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(104),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(104),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(104),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(104),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(106),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(104),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(104),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(104),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(104),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(104),
    [anon_sym_ssl] = ACTIONS(104),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(104),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(104),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(104),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(104),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(104),
  },
  [21] = {
    [ts_builtin_sym_end] = ACTIONS(108),
    [anon_sym_AMP_AMP] = ACTIONS(110),
    [anon_sym_and] = ACTIONS(110),
    [anon_sym_xor] = ACTIONS(112),
    [anon_sym_CARET_CARET] = ACTIONS(112),
    [anon_sym_or] = ACTIONS(108),
    [anon_sym_PIPE_PIPE] = ACTIONS(108),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(108),
    [anon_sym_RPAREN] = ACTIONS(108),
    [anon_sym_not] = ACTIONS(108),
    [anon_sym_BANG] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(108),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(108),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(114),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(108),
    [anon_sym_ip_DOTsrc] = ACTIONS(114),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(108),
    [anon_sym_http_DOTcookie] = ACTIONS(108),
    [anon_sym_http_DOThost] = ACTIONS(108),
    [anon_sym_http_DOTreferer] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(114),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_http_DOTuser_agent] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(108),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(114),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(108),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(108),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(108),
    [anon_sym_ssl] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(108),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(108),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(108),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(108),
  },
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(108),
    [anon_sym_AMP_AMP] = ACTIONS(110),
    [anon_sym_and] = ACTIONS(110),
    [anon_sym_xor] = ACTIONS(108),
    [anon_sym_CARET_CARET] = ACTIONS(108),
    [anon_sym_or] = ACTIONS(108),
    [anon_sym_PIPE_PIPE] = ACTIONS(108),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(108),
    [anon_sym_RPAREN] = ACTIONS(108),
    [anon_sym_not] = ACTIONS(108),
    [anon_sym_BANG] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(108),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(108),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(114),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(108),
    [anon_sym_ip_DOTsrc] = ACTIONS(114),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(108),
    [anon_sym_http_DOTcookie] = ACTIONS(108),
    [anon_sym_http_DOThost] = ACTIONS(108),
    [anon_sym_http_DOTreferer] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(114),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_http_DOTuser_agent] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(108),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(114),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(108),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(108),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(108),
    [anon_sym_ssl] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(108),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(108),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(108),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(108),
  },
  [23] = {
    [ts_builtin_sym_end] = ACTIONS(108),
    [anon_sym_AMP_AMP] = ACTIONS(108),
    [anon_sym_and] = ACTIONS(108),
    [anon_sym_xor] = ACTIONS(108),
    [anon_sym_CARET_CARET] = ACTIONS(108),
    [anon_sym_or] = ACTIONS(108),
    [anon_sym_PIPE_PIPE] = ACTIONS(108),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(108),
    [anon_sym_RPAREN] = ACTIONS(108),
    [anon_sym_not] = ACTIONS(108),
    [anon_sym_BANG] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(108),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(108),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(114),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(108),
    [anon_sym_ip_DOTsrc] = ACTIONS(114),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(108),
    [anon_sym_http_DOTcookie] = ACTIONS(108),
    [anon_sym_http_DOThost] = ACTIONS(108),
    [anon_sym_http_DOTreferer] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(114),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_http_DOTuser_agent] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(108),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(114),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(108),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(108),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(108),
    [anon_sym_ssl] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(108),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(108),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(108),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(108),
  },
  [24] = {
    [ts_builtin_sym_end] = ACTIONS(116),
    [anon_sym_AMP_AMP] = ACTIONS(110),
    [anon_sym_and] = ACTIONS(110),
    [anon_sym_xor] = ACTIONS(112),
    [anon_sym_CARET_CARET] = ACTIONS(112),
    [anon_sym_or] = ACTIONS(118),
    [anon_sym_PIPE_PIPE] = ACTIONS(118),
    [sym_comment] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(116),
    [anon_sym_not] = ACTIONS(116),
    [anon_sym_BANG] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(116),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(116),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(116),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(116),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(116),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(120),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(116),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(116),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(116),
    [anon_sym_ip_DOTsrc] = ACTIONS(120),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(116),
    [anon_sym_http_DOTcookie] = ACTIONS(116),
    [anon_sym_http_DOThost] = ACTIONS(116),
    [anon_sym_http_DOTreferer] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(116),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(120),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(120),
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
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(124), 4,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_ip_DOTsrc,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(122), 46,
      anon_sym_LPAREN,
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
  [58] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(128), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(126), 14,
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
  [82] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(130), 1,
      anon_sym_in,
    ACTIONS(134), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(132), 13,
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
  [108] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(136), 1,
      anon_sym_in,
    ACTIONS(140), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(138), 10,
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
  [131] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(144), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(142), 11,
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
  [152] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(146), 1,
      anon_sym_RPAREN,
    ACTIONS(110), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(112), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(118), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [171] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(148), 5,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [182] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(150), 1,
      anon_sym_RBRACE,
    ACTIONS(152), 1,
      sym_ipv4,
    STATE(32), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [197] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(155), 1,
      anon_sym_in,
    ACTIONS(157), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [210] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(159), 1,
      anon_sym_RBRACE,
    ACTIONS(161), 1,
      sym_ipv4,
    STATE(32), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [225] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(161), 1,
      sym_ipv4,
    STATE(34), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [237] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(161), 1,
      sym_ipv4,
    STATE(19), 2,
      sym__ip,
      sym_ip_range,
  [248] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(163), 1,
      anon_sym_RBRACE,
    ACTIONS(165), 1,
      sym_number,
    STATE(39), 1,
      aux_sym_number_set_repeat1,
  [261] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(167), 1,
      anon_sym_RBRACE,
    ACTIONS(169), 1,
      sym_string,
    STATE(41), 1,
      aux_sym_string_set_repeat1,
  [274] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(171), 1,
      anon_sym_RBRACE,
    ACTIONS(173), 1,
      sym_number,
    STATE(39), 1,
      aux_sym_number_set_repeat1,
  [287] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(19), 1,
      sym_boolean,
    ACTIONS(176), 2,
      anon_sym_true,
      anon_sym_false,
  [298] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(178), 1,
      anon_sym_RBRACE,
    ACTIONS(180), 1,
      sym_string,
    STATE(41), 1,
      aux_sym_string_set_repeat1,
  [311] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(183), 1,
      sym_string,
    STATE(38), 1,
      aux_sym_string_set_repeat1,
  [321] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(185), 1,
      anon_sym_LBRACE,
    STATE(20), 1,
      sym_number_set,
  [331] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(187), 1,
      anon_sym_LBRACE,
    STATE(20), 1,
      sym_ip_set,
  [341] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(189), 1,
      sym_number,
    STATE(37), 1,
      aux_sym_number_set_repeat1,
  [351] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(191), 1,
      anon_sym_LBRACE,
    STATE(20), 1,
      sym_string_set,
  [361] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(193), 1,
      sym_number,
  [368] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(193), 1,
      sym_string,
  [375] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(195), 1,
      aux_sym_ip_range_token1,
  [382] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(197), 1,
      ts_builtin_sym_end,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(25)] = 0,
  [SMALL_STATE(26)] = 58,
  [SMALL_STATE(27)] = 82,
  [SMALL_STATE(28)] = 108,
  [SMALL_STATE(29)] = 131,
  [SMALL_STATE(30)] = 152,
  [SMALL_STATE(31)] = 171,
  [SMALL_STATE(32)] = 182,
  [SMALL_STATE(33)] = 197,
  [SMALL_STATE(34)] = 210,
  [SMALL_STATE(35)] = 225,
  [SMALL_STATE(36)] = 237,
  [SMALL_STATE(37)] = 248,
  [SMALL_STATE(38)] = 261,
  [SMALL_STATE(39)] = 274,
  [SMALL_STATE(40)] = 287,
  [SMALL_STATE(41)] = 298,
  [SMALL_STATE(42)] = 311,
  [SMALL_STATE(43)] = 321,
  [SMALL_STATE(44)] = 331,
  [SMALL_STATE(45)] = 341,
  [SMALL_STATE(46)] = 351,
  [SMALL_STATE(47)] = 361,
  [SMALL_STATE(48)] = 368,
  [SMALL_STATE(49)] = 375,
  [SMALL_STATE(50)] = 382,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [13] = {.entry = {.count = 1, .reusable = false}}, SHIFT(29),
  [15] = {.entry = {.count = 1, .reusable = false}}, SHIFT(31),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [21] = {.entry = {.count = 1, .reusable = false}}, SHIFT(26),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [25] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [27] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(6),
  [30] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(25),
  [33] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(29),
  [36] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(29),
  [39] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(31),
  [42] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(31),
  [45] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(26),
  [48] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(26),
  [51] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(5),
  [54] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [56] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__expression, 1),
  [58] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [60] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__expression, 1),
  [62] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean_field, 1),
  [64] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean_field, 1),
  [66] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [68] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [70] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [72] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 3),
  [74] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 3),
  [76] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [78] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [80] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3),
  [82] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3),
  [84] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [86] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [88] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [90] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [92] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [94] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [96] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [98] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [100] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [102] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [104] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [106] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [108] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 1),
  [110] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [112] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [114] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 1),
  [116] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [118] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [120] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [122] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [124] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [126] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [128] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [130] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [132] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [134] = {.entry = {.count = 1, .reusable = false}}, SHIFT(48),
  [136] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [138] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [140] = {.entry = {.count = 1, .reusable = false}}, SHIFT(47),
  [142] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [144] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [146] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [148] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [150] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [152] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(7),
  [155] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [157] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [159] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [161] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [163] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [165] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [167] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [169] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [171] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [173] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(39),
  [176] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [178] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [180] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(41),
  [183] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [185] = {.entry = {.count = 1, .reusable = true}}, SHIFT(45),
  [187] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [189] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [191] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [193] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [195] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [197] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
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
