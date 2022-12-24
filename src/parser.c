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
#define STATE_COUNT 48
#define LARGE_STATE_COUNT 23
#define SYMBOL_COUNT 104
#define ALIAS_COUNT 0
#define TOKEN_COUNT 83
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 5
#define MAX_ALIAS_SEQUENCE_LENGTH 3
#define PRODUCTION_ID_COUNT 3

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
  anon_sym_eq = 10,
  anon_sym_ne = 11,
  anon_sym_lt = 12,
  anon_sym_le = 13,
  anon_sym_gt = 14,
  anon_sym_ge = 15,
  anon_sym_EQ_EQ = 16,
  anon_sym_BANG_EQ = 17,
  anon_sym_LT = 18,
  anon_sym_LT_EQ = 19,
  anon_sym_GT = 20,
  anon_sym_GT_EQ = 21,
  anon_sym_contains = 22,
  anon_sym_matches = 23,
  anon_sym_TILDE = 24,
  anon_sym_LPAREN = 25,
  anon_sym_RPAREN = 26,
  sym_number = 27,
  sym_ipv4 = 28,
  sym_ip_range = 29,
  sym_string = 30,
  anon_sym_true = 31,
  anon_sym_false = 32,
  anon_sym_not = 33,
  anon_sym_BANG = 34,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTsec = 35,
  anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec = 36,
  anon_sym_ip_DOTgeoip_DOTasnum = 37,
  anon_sym_cf_DOTbot_management_DOTscore = 38,
  anon_sym_cf_DOTedge_DOTserver_port = 39,
  anon_sym_cf_DOTthreat_score = 40,
  anon_sym_cf_DOTwaf_DOTscore = 41,
  anon_sym_cf_DOTwaf_DOTscore_DOTsqli = 42,
  anon_sym_cf_DOTwaf_DOTscore_DOTxss = 43,
  anon_sym_cf_DOTwaf_DOTscore_DOTrce = 44,
  anon_sym_ip_DOTsrc = 45,
  anon_sym_cf_DOTedge_DOTserver_ip = 46,
  anon_sym_http_DOTcookie = 47,
  anon_sym_http_DOThost = 48,
  anon_sym_http_DOTreferer = 49,
  anon_sym_http_DOTrequest_DOTfull_uri = 50,
  anon_sym_http_DOTrequest_DOTmethod = 51,
  anon_sym_http_DOTrequest_DOTcookies = 52,
  anon_sym_http_DOTrequest_DOTuri = 53,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 54,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 55,
  anon_sym_http_DOTuser_agent = 56,
  anon_sym_http_DOTrequest_DOTversion = 57,
  anon_sym_http_DOTx_forwarded_for = 58,
  anon_sym_ip_DOTsrc_DOTlat = 59,
  anon_sym_ip_DOTsrc_DOTlon = 60,
  anon_sym_ip_DOTsrc_DOTcity = 61,
  anon_sym_ip_DOTsrc_DOTpostal_code = 62,
  anon_sym_ip_DOTsrc_DOTmetro_code = 63,
  anon_sym_ip_DOTgeoip_DOTcontinent = 64,
  anon_sym_ip_DOTgeoip_DOTcountry = 65,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 66,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 67,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 68,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 69,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 70,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 71,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 72,
  anon_sym_cf_DOThostname_DOTmetadata = 73,
  anon_sym_cf_DOTworker_DOTupstream_zone = 74,
  anon_sym_cf_DOTrandom_seed = 75,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 76,
  anon_sym_ssl = 77,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 78,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 79,
  anon_sym_cf_DOTclient_DOTbot = 80,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 81,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 82,
  sym_source_file = 83,
  sym__expression = 84,
  sym_not_expression = 85,
  sym_in_expression = 86,
  sym_compound_expression = 87,
  sym_ip_set = 88,
  sym_string_set = 89,
  sym_number_set = 90,
  sym_simple_expression = 91,
  sym_group = 92,
  sym__ip = 93,
  sym_boolean = 94,
  sym_not_operator = 95,
  sym_number_field = 96,
  sym_ip_field = 97,
  sym_string_field = 98,
  sym_boolean_field = 99,
  aux_sym_source_file_repeat1 = 100,
  aux_sym_ip_set_repeat1 = 101,
  aux_sym_string_set_repeat1 = 102,
  aux_sym_number_set_repeat1 = 103,
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
  [sym_ipv4] = "ipv4",
  [sym_ip_range] = "ip_range",
  [sym_string] = "string",
  [anon_sym_true] = "true",
  [anon_sym_false] = "false",
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
  [sym__ip] = "_ip",
  [sym_boolean] = "boolean",
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
  [sym_ipv4] = sym_ipv4,
  [sym_ip_range] = sym_ip_range,
  [sym_string] = sym_string,
  [anon_sym_true] = anon_sym_true,
  [anon_sym_false] = anon_sym_false,
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
  [sym__ip] = sym__ip,
  [sym_boolean] = sym_boolean,
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
  [sym_ipv4] = {
    .visible = true,
    .named = true,
  },
  [sym_ip_range] = {
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
  [sym__ip] = {
    .visible = false,
    .named = true,
  },
  [sym_boolean] = {
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
  field_left = 2,
  field_operator = 3,
  field_right = 4,
  field_value = 5,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_field] = "field",
  [field_left] = "left",
  [field_operator] = "operator",
  [field_right] = "right",
  [field_value] = "value",
};

static const TSFieldMapSlice ts_field_map_slices[PRODUCTION_ID_COUNT] = {
  [1] = {.index = 0, .length = 3},
  [2] = {.index = 3, .length = 3},
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
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(477);
      if (lookahead == '!') ADVANCE(522);
      if (lookahead == '"') ADVANCE(1);
      if (lookahead == '&') ADVANCE(2);
      if (lookahead == '(') ADVANCE(502);
      if (lookahead == ')') ADVANCE(503);
      if (lookahead == '2') ADVANCE(504);
      if (lookahead == '<') ADVANCE(495);
      if (lookahead == '=') ADVANCE(42);
      if (lookahead == '>') ADVANCE(497);
      if (lookahead == '^') ADVANCE(43);
      if (lookahead == 'a') ADVANCE(273);
      if (lookahead == 'c') ADVANCE(199);
      if (lookahead == 'e') ADVANCE(343);
      if (lookahead == 'f') ADVANCE(70);
      if (lookahead == 'g') ADVANCE(137);
      if (lookahead == 'h') ADVANCE(424);
      if (lookahead == 'i') ADVANCE(274);
      if (lookahead == 'l') ADVANCE(138);
      if (lookahead == 'm') ADVANCE(76);
      if (lookahead == 'n') ADVANCE(139);
      if (lookahead == 'o') ADVANCE(346);
      if (lookahead == 'r') ADVANCE(71);
      if (lookahead == 's') ADVANCE(386);
      if (lookahead == 't') ADVANCE(347);
      if (lookahead == 'x') ADVANCE(301);
      if (lookahead == '{') ADVANCE(485);
      if (lookahead == '|') ADVANCE(475);
      if (lookahead == '}') ADVANCE(486);
      if (lookahead == '~') ADVANCE(501);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(508);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(507);
      END_STATE();
    case 1:
      if (lookahead == '"') ADVANCE(518);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(1);
      END_STATE();
    case 2:
      if (lookahead == '&') ADVANCE(479);
      END_STATE();
    case 3:
      if (lookahead == '.') ADVANCE(36);
      END_STATE();
    case 4:
      if (lookahead == '.') ADVANCE(36);
      if (lookahead == '5') ADVANCE(5);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(3);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(7);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(36);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(3);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(36);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(7);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(36);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(3);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(97);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(207);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(106);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(81);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(99);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(118);
      END_STATE();
    case 14:
      if (lookahead == '.') ADVANCE(206);
      END_STATE();
    case 15:
      if (lookahead == '.') ADVANCE(248);
      END_STATE();
    case 16:
      if (lookahead == '.') ADVANCE(270);
      END_STATE();
    case 17:
      if (lookahead == '.') ADVANCE(37);
      END_STATE();
    case 18:
      if (lookahead == '.') ADVANCE(37);
      if (lookahead == '5') ADVANCE(19);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(17);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(21);
      END_STATE();
    case 19:
      if (lookahead == '.') ADVANCE(37);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(17);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(37);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(21);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(37);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(17);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(451);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(219);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(337);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(389);
      END_STATE();
    case 26:
      if (lookahead == '.') ADVANCE(38);
      END_STATE();
    case 27:
      if (lookahead == '.') ADVANCE(38);
      if (lookahead == '5') ADVANCE(28);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(26);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(30);
      END_STATE();
    case 28:
      if (lookahead == '.') ADVANCE(38);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(26);
      END_STATE();
    case 29:
      if (lookahead == '.') ADVANCE(38);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(30);
      END_STATE();
    case 30:
      if (lookahead == '.') ADVANCE(38);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(26);
      END_STATE();
    case 31:
      if (lookahead == '.') ADVANCE(268);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(110);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(398);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(373);
      END_STATE();
    case 35:
      if (lookahead == '1') ADVANCE(58);
      if (lookahead == '2') ADVANCE(69);
      END_STATE();
    case 36:
      if (lookahead == '2') ADVANCE(27);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(29);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(30);
      END_STATE();
    case 37:
      if (lookahead == '2') ADVANCE(511);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(514);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(513);
      END_STATE();
    case 38:
      if (lookahead == '2') ADVANCE(18);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(20);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(21);
      END_STATE();
    case 39:
      if (lookahead == '2') ADVANCE(4);
      if (lookahead == '}') ADVANCE(486);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(6);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(39)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(7);
      END_STATE();
    case 40:
      if (lookahead == '3') ADVANCE(516);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(517);
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(515);
      END_STATE();
    case 41:
      if (lookahead == '3') ADVANCE(52);
      END_STATE();
    case 42:
      if (lookahead == '=') ADVANCE(493);
      END_STATE();
    case 43:
      if (lookahead == '^') ADVANCE(482);
      END_STATE();
    case 44:
      if (lookahead == '_') ADVANCE(265);
      END_STATE();
    case 45:
      if (lookahead == '_') ADVANCE(227);
      END_STATE();
    case 46:
      if (lookahead == '_') ADVANCE(474);
      END_STATE();
    case 47:
      if (lookahead == '_') ADVANCE(35);
      END_STATE();
    case 48:
      if (lookahead == '_') ADVANCE(380);
      END_STATE();
    case 49:
      if (lookahead == '_') ADVANCE(202);
      END_STATE();
    case 50:
      if (lookahead == '_') ADVANCE(117);
      END_STATE();
    case 51:
      if (lookahead == '_') ADVANCE(107);
      END_STATE();
    case 52:
      if (lookahead == '_') ADVANCE(217);
      END_STATE();
    case 53:
      if (lookahead == '_') ADVANCE(455);
      END_STATE();
    case 54:
      if (lookahead == '_') ADVANCE(80);
      END_STATE();
    case 55:
      if (lookahead == '_') ADVANCE(160);
      END_STATE();
    case 56:
      if (lookahead == '_') ADVANCE(230);
      END_STATE();
    case 57:
      if (lookahead == '_') ADVANCE(458);
      END_STATE();
    case 58:
      if (lookahead == '_') ADVANCE(235);
      END_STATE();
    case 59:
      if (lookahead == '_') ADVANCE(460);
      END_STATE();
    case 60:
      if (lookahead == '_') ADVANCE(401);
      END_STATE();
    case 61:
      if (lookahead == '_') ADVANCE(135);
      END_STATE();
    case 62:
      if (lookahead == '_') ADVANCE(100);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(204);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(95);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(112);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(409);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(114);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(116);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(247);
      END_STATE();
    case 70:
      if (lookahead == 'a') ADVANCE(255);
      END_STATE();
    case 71:
      if (lookahead == 'a') ADVANCE(468);
      END_STATE();
    case 72:
      if (lookahead == 'a') ADVANCE(200);
      if (lookahead == 'o') ADVANCE(349);
      END_STATE();
    case 73:
      if (lookahead == 'a') ADVANCE(41);
      if (lookahead == 's') ADVANCE(61);
      END_STATE();
    case 74:
      if (lookahead == 'a') ADVANCE(561);
      END_STATE();
    case 75:
      if (lookahead == 'a') ADVANCE(226);
      END_STATE();
    case 76:
      if (lookahead == 'a') ADVANCE(413);
      END_STATE();
    case 77:
      if (lookahead == 'a') ADVANCE(267);
      END_STATE();
    case 78:
      if (lookahead == 'a') ADVANCE(262);
      END_STATE();
    case 79:
      if (lookahead == 'a') ADVANCE(269);
      END_STATE();
    case 80:
      if (lookahead == 'a') ADVANCE(459);
      END_STATE();
    case 81:
      if (lookahead == 'a') ADVANCE(390);
      if (lookahead == 'c') ADVANCE(298);
      if (lookahead == 'i') ADVANCE(392);
      if (lookahead == 's') ADVANCE(452);
      END_STATE();
    case 82:
      if (lookahead == 'a') ADVANCE(134);
      END_STATE();
    case 83:
      if (lookahead == 'a') ADVANCE(430);
      END_STATE();
    case 84:
      if (lookahead == 'a') ADVANCE(418);
      if (lookahead == 'o') ADVANCE(275);
      END_STATE();
    case 85:
      if (lookahead == 'a') ADVANCE(358);
      END_STATE();
    case 86:
      if (lookahead == 'a') ADVANCE(393);
      END_STATE();
    case 87:
      if (lookahead == 'a') ADVANCE(408);
      END_STATE();
    case 88:
      if (lookahead == 'a') ADVANCE(435);
      END_STATE();
    case 89:
      if (lookahead == 'a') ADVANCE(429);
      END_STATE();
    case 90:
      if (lookahead == 'a') ADVANCE(431);
      END_STATE();
    case 91:
      if (lookahead == 'a') ADVANCE(278);
      END_STATE();
    case 92:
      if (lookahead == 'a') ADVANCE(209);
      END_STATE();
    case 93:
      if (lookahead == 'a') ADVANCE(266);
      END_STATE();
    case 94:
      if (lookahead == 'a') ADVANCE(283);
      END_STATE();
    case 95:
      if (lookahead == 'a') ADVANCE(210);
      END_STATE();
    case 96:
      if (lookahead == 'a') ADVANCE(289);
      END_STATE();
    case 97:
      if (lookahead == 'b') ADVANCE(305);
      if (lookahead == 'c') ADVANCE(254);
      if (lookahead == 'e') ADVANCE(120);
      if (lookahead == 'h') ADVANCE(302);
      if (lookahead == 'r') ADVANCE(91);
      if (lookahead == 't') ADVANCE(215);
      if (lookahead == 'w') ADVANCE(72);
      END_STATE();
    case 98:
      if (lookahead == 'b') ADVANCE(126);
      END_STATE();
    case 99:
      if (lookahead == 'b') ADVANCE(313);
      END_STATE();
    case 100:
      if (lookahead == 'b') ADVANCE(316);
      END_STATE();
    case 101:
      if (lookahead == 'c') ADVANCE(214);
      END_STATE();
    case 102:
      if (lookahead == 'c') ADVANCE(533);
      END_STATE();
    case 103:
      if (lookahead == 'c') ADVANCE(523);
      END_STATE();
    case 104:
      if (lookahead == 'c') ADVANCE(524);
      END_STATE();
    case 105:
      if (lookahead == 'c') ADVANCE(232);
      if (lookahead == 'l') ADVANCE(84);
      if (lookahead == 'm') ADVANCE(172);
      if (lookahead == 'p') ADVANCE(322);
      END_STATE();
    case 106:
      if (lookahead == 'c') ADVANCE(306);
      if (lookahead == 'h') ADVANCE(319);
      if (lookahead == 'r') ADVANCE(142);
      if (lookahead == 'u') ADVANCE(395);
      if (lookahead == 'x') ADVANCE(49);
      END_STATE();
    case 107:
      if (lookahead == 'c') ADVANCE(320);
      END_STATE();
    case 108:
      if (lookahead == 'c') ADVANCE(146);
      END_STATE();
    case 109:
      if (lookahead == 'c') ADVANCE(448);
      END_STATE();
    case 110:
      if (lookahead == 'c') ADVANCE(189);
      END_STATE();
    case 111:
      if (lookahead == 'c') ADVANCE(324);
      END_STATE();
    case 112:
      if (lookahead == 'c') ADVANCE(323);
      END_STATE();
    case 113:
      if (lookahead == 'c') ADVANCE(325);
      END_STATE();
    case 114:
      if (lookahead == 'c') ADVANCE(326);
      END_STATE();
    case 115:
      if (lookahead == 'c') ADVANCE(328);
      END_STATE();
    case 116:
      if (lookahead == 'c') ADVANCE(327);
      END_STATE();
    case 117:
      if (lookahead == 'c') ADVANCE(260);
      END_STATE();
    case 118:
      if (lookahead == 'c') ADVANCE(330);
      if (lookahead == 'f') ADVANCE(454);
      if (lookahead == 'm') ADVANCE(180);
      if (lookahead == 't') ADVANCE(244);
      if (lookahead == 'u') ADVANCE(362);
      if (lookahead == 'v') ADVANCE(178);
      END_STATE();
    case 119:
      if (lookahead == 'd') ADVANCE(480);
      END_STATE();
    case 120:
      if (lookahead == 'd') ADVANCE(208);
      END_STATE();
    case 121:
      if (lookahead == 'd') ADVANCE(563);
      END_STATE();
    case 122:
      if (lookahead == 'd') ADVANCE(539);
      END_STATE();
    case 123:
      if (lookahead == 'd') ADVANCE(569);
      END_STATE();
    case 124:
      if (lookahead == 'd') ADVANCE(570);
      END_STATE();
    case 125:
      if (lookahead == 'd') ADVANCE(567);
      END_STATE();
    case 126:
      if (lookahead == 'd') ADVANCE(225);
      END_STATE();
    case 127:
      if (lookahead == 'd') ADVANCE(300);
      END_STATE();
    case 128:
      if (lookahead == 'd') ADVANCE(62);
      END_STATE();
    case 129:
      if (lookahead == 'd') ADVANCE(159);
      END_STATE();
    case 130:
      if (lookahead == 'd') ADVANCE(147);
      END_STATE();
    case 131:
      if (lookahead == 'd') ADVANCE(148);
      END_STATE();
    case 132:
      if (lookahead == 'd') ADVANCE(151);
      END_STATE();
    case 133:
      if (lookahead == 'd') ADVANCE(152);
      END_STATE();
    case 134:
      if (lookahead == 'd') ADVANCE(88);
      END_STATE();
    case 135:
      if (lookahead == 'd') ADVANCE(185);
      END_STATE();
    case 136:
      if (lookahead == 'd') ADVANCE(63);
      END_STATE();
    case 137:
      if (lookahead == 'e') ADVANCE(492);
      if (lookahead == 't') ADVANCE(491);
      END_STATE();
    case 138:
      if (lookahead == 'e') ADVANCE(490);
      if (lookahead == 't') ADVANCE(489);
      END_STATE();
    case 139:
      if (lookahead == 'e') ADVANCE(488);
      if (lookahead == 'o') ADVANCE(414);
      END_STATE();
    case 140:
      if (lookahead == 'e') ADVANCE(519);
      END_STATE();
    case 141:
      if (lookahead == 'e') ADVANCE(520);
      END_STATE();
    case 142:
      if (lookahead == 'e') ADVANCE(201);
      END_STATE();
    case 143:
      if (lookahead == 'e') ADVANCE(535);
      END_STATE();
    case 144:
      if (lookahead == 'e') ADVANCE(529);
      END_STATE();
    case 145:
      if (lookahead == 'e') ADVANCE(528);
      END_STATE();
    case 146:
      if (lookahead == 'e') ADVANCE(532);
      END_STATE();
    case 147:
      if (lookahead == 'e') ADVANCE(551);
      END_STATE();
    case 148:
      if (lookahead == 'e') ADVANCE(550);
      END_STATE();
    case 149:
      if (lookahead == 'e') ADVANCE(526);
      END_STATE();
    case 150:
      if (lookahead == 'e') ADVANCE(562);
      END_STATE();
    case 151:
      if (lookahead == 'e') ADVANCE(554);
      END_STATE();
    case 152:
      if (lookahead == 'e') ADVANCE(555);
      END_STATE();
    case 153:
      if (lookahead == 'e') ADVANCE(345);
      END_STATE();
    case 154:
      if (lookahead == 'e') ADVANCE(466);
      END_STATE();
    case 155:
      if (lookahead == 'e') ADVANCE(303);
      END_STATE();
    case 156:
      if (lookahead == 'e') ADVANCE(382);
      END_STATE();
    case 157:
      if (lookahead == 'e') ADVANCE(121);
      END_STATE();
    case 158:
      if (lookahead == 'e') ADVANCE(367);
      END_STATE();
    case 159:
      if (lookahead == 'e') ADVANCE(136);
      END_STATE();
    case 160:
      if (lookahead == 'e') ADVANCE(457);
      END_STATE();
    case 161:
      if (lookahead == 'e') ADVANCE(109);
      END_STATE();
    case 162:
      if (lookahead == 'e') ADVANCE(360);
      END_STATE();
    case 163:
      if (lookahead == 'e') ADVANCE(33);
      END_STATE();
    case 164:
      if (lookahead == 'e') ADVANCE(103);
      END_STATE();
    case 165:
      if (lookahead == 'e') ADVANCE(104);
      END_STATE();
    case 166:
      if (lookahead == 'e') ADVANCE(350);
      END_STATE();
    case 167:
      if (lookahead == 'e') ADVANCE(128);
      END_STATE();
    case 168:
      if (lookahead == 'e') ADVANCE(123);
      END_STATE();
    case 169:
      if (lookahead == 'e') ADVANCE(93);
      END_STATE();
    case 170:
      if (lookahead == 'e') ADVANCE(351);
      END_STATE();
    case 171:
      if (lookahead == 'e') ADVANCE(124);
      END_STATE();
    case 172:
      if (lookahead == 'e') ADVANCE(433);
      END_STATE();
    case 173:
      if (lookahead == 'e') ADVANCE(385);
      END_STATE();
    case 174:
      if (lookahead == 'e') ADVANCE(125);
      END_STATE();
    case 175:
      if (lookahead == 'e') ADVANCE(31);
      END_STATE();
    case 176:
      if (lookahead == 'e') ADVANCE(363);
      END_STATE();
    case 177:
      if (lookahead == 'e') ADVANCE(96);
      END_STATE();
    case 178:
      if (lookahead == 'e') ADVANCE(366);
      END_STATE();
    case 179:
      if (lookahead == 'e') ADVANCE(432);
      END_STATE();
    case 180:
      if (lookahead == 'e') ADVANCE(425);
      END_STATE();
    case 181:
      if (lookahead == 'e') ADVANCE(157);
      END_STATE();
    case 182:
      if (lookahead == 'e') ADVANCE(370);
      END_STATE();
    case 183:
      if (lookahead == 'e') ADVANCE(356);
      END_STATE();
    case 184:
      if (lookahead == 'e') ADVANCE(357);
      END_STATE();
    case 185:
      if (lookahead == 'e') ADVANCE(442);
      END_STATE();
    case 186:
      if (lookahead == 'e') ADVANCE(284);
      END_STATE();
    case 187:
      if (lookahead == 'e') ADVANCE(83);
      END_STATE();
    case 188:
      if (lookahead == 'e') ADVANCE(372);
      END_STATE();
    case 189:
      if (lookahead == 'e') ADVANCE(378);
      END_STATE();
    case 190:
      if (lookahead == 'e') ADVANCE(287);
      END_STATE();
    case 191:
      if (lookahead == 'e') ADVANCE(272);
      END_STATE();
    case 192:
      if (lookahead == 'e') ADVANCE(405);
      END_STATE();
    case 193:
      if (lookahead == 'e') ADVANCE(292);
      END_STATE();
    case 194:
      if (lookahead == 'e') ADVANCE(296);
      END_STATE();
    case 195:
      if (lookahead == 'e') ADVANCE(407);
      END_STATE();
    case 196:
      if (lookahead == 'e') ADVANCE(293);
      END_STATE();
    case 197:
      if (lookahead == 'e') ADVANCE(402);
      END_STATE();
    case 198:
      if (lookahead == 'e') ADVANCE(381);
      END_STATE();
    case 199:
      if (lookahead == 'f') ADVANCE(8);
      if (lookahead == 'o') ADVANCE(280);
      END_STATE();
    case 200:
      if (lookahead == 'f') ADVANCE(25);
      END_STATE();
    case 201:
      if (lookahead == 'f') ADVANCE(188);
      if (lookahead == 'q') ADVANCE(456);
      END_STATE();
    case 202:
      if (lookahead == 'f') ADVANCE(308);
      END_STATE();
    case 203:
      if (lookahead == 'f') ADVANCE(239);
      END_STATE();
    case 204:
      if (lookahead == 'f') ADVANCE(315);
      END_STATE();
    case 205:
      if (lookahead == 'f') ADVANCE(240);
      END_STATE();
    case 206:
      if (lookahead == 'f') ADVANCE(464);
      if (lookahead == 'u') ADVANCE(365);
      END_STATE();
    case 207:
      if (lookahead == 'g') ADVANCE(155);
      if (lookahead == 's') ADVANCE(354);
      END_STATE();
    case 208:
      if (lookahead == 'g') ADVANCE(163);
      END_STATE();
    case 209:
      if (lookahead == 'g') ADVANCE(191);
      END_STATE();
    case 210:
      if (lookahead == 'g') ADVANCE(193);
      END_STATE();
    case 211:
      if (lookahead == 'h') ADVANCE(542);
      END_STATE();
    case 212:
      if (lookahead == 'h') ADVANCE(558);
      END_STATE();
    case 213:
      if (lookahead == 'h') ADVANCE(560);
      END_STATE();
    case 214:
      if (lookahead == 'h') ADVANCE(156);
      END_STATE();
    case 215:
      if (lookahead == 'h') ADVANCE(361);
      if (lookahead == 'l') ADVANCE(388);
      END_STATE();
    case 216:
      if (lookahead == 'h') ADVANCE(309);
      END_STATE();
    case 217:
      if (lookahead == 'h') ADVANCE(86);
      END_STATE();
    case 218:
      if (lookahead == 'h') ADVANCE(32);
      END_STATE();
    case 219:
      if (lookahead == 'h') ADVANCE(444);
      END_STATE();
    case 220:
      if (lookahead == 'i') ADVANCE(541);
      END_STATE();
    case 221:
      if (lookahead == 'i') ADVANCE(530);
      END_STATE();
    case 222:
      if (lookahead == 'i') ADVANCE(557);
      END_STATE();
    case 223:
      if (lookahead == 'i') ADVANCE(538);
      END_STATE();
    case 224:
      if (lookahead == 'i') ADVANCE(556);
      END_STATE();
    case 225:
      if (lookahead == 'i') ADVANCE(465);
      END_STATE();
    case 226:
      if (lookahead == 'i') ADVANCE(282);
      END_STATE();
    case 227:
      if (lookahead == 'i') ADVANCE(333);
      if (lookahead == 'p') ADVANCE(314);
      END_STATE();
    case 228:
      if (lookahead == 'i') ADVANCE(203);
      END_STATE();
    case 229:
      if (lookahead == 'i') ADVANCE(186);
      END_STATE();
    case 230:
      if (lookahead == 'i') ADVANCE(285);
      END_STATE();
    case 231:
      if (lookahead == 'i') ADVANCE(297);
      END_STATE();
    case 232:
      if (lookahead == 'i') ADVANCE(417);
      END_STATE();
    case 233:
      if (lookahead == 'i') ADVANCE(307);
      END_STATE();
    case 234:
      if (lookahead == 'i') ADVANCE(321);
      END_STATE();
    case 235:
      if (lookahead == 'i') ADVANCE(410);
      END_STATE();
    case 236:
      if (lookahead == 'i') ADVANCE(143);
      END_STATE();
    case 237:
      if (lookahead == 'i') ADVANCE(311);
      END_STATE();
    case 238:
      if (lookahead == 'i') ADVANCE(312);
      END_STATE();
    case 239:
      if (lookahead == 'i') ADVANCE(167);
      END_STATE();
    case 240:
      if (lookahead == 'i') ADVANCE(171);
      END_STATE();
    case 241:
      if (lookahead == 'i') ADVANCE(335);
      END_STATE();
    case 242:
      if (lookahead == 'i') ADVANCE(173);
      END_STATE();
    case 243:
      if (lookahead == 'i') ADVANCE(406);
      END_STATE();
    case 244:
      if (lookahead == 'i') ADVANCE(271);
      END_STATE();
    case 245:
      if (lookahead == 'i') ADVANCE(205);
      END_STATE();
    case 246:
      if (lookahead == 'i') ADVANCE(190);
      END_STATE();
    case 247:
      if (lookahead == 'i') ADVANCE(411);
      END_STATE();
    case 248:
      if (lookahead == 'j') ADVANCE(73);
      if (lookahead == 's') ADVANCE(115);
      if (lookahead == 'v') ADVANCE(182);
      END_STATE();
    case 249:
      if (lookahead == 'k') ADVANCE(158);
      END_STATE();
    case 250:
      if (lookahead == 'k') ADVANCE(168);
      END_STATE();
    case 251:
      if (lookahead == 'k') ADVANCE(236);
      END_STATE();
    case 252:
      if (lookahead == 'k') ADVANCE(242);
      END_STATE();
    case 253:
      if (lookahead == 'l') ADVANCE(565);
      END_STATE();
    case 254:
      if (lookahead == 'l') ADVANCE(229);
      END_STATE();
    case 255:
      if (lookahead == 'l') ADVANCE(387);
      END_STATE();
    case 256:
      if (lookahead == 'l') ADVANCE(258);
      END_STATE();
    case 257:
      if (lookahead == 'l') ADVANCE(221);
      END_STATE();
    case 258:
      if (lookahead == 'l') ADVANCE(57);
      END_STATE();
    case 259:
      if (lookahead == 'l') ADVANCE(59);
      END_STATE();
    case 260:
      if (lookahead == 'l') ADVANCE(246);
      END_STATE();
    case 261:
      if (lookahead == 'l') ADVANCE(259);
      END_STATE();
    case 262:
      if (lookahead == 'l') ADVANCE(65);
      END_STATE();
    case 263:
      if (lookahead == 'm') ADVANCE(525);
      END_STATE();
    case 264:
      if (lookahead == 'm') ADVANCE(60);
      END_STATE();
    case 265:
      if (lookahead == 'm') ADVANCE(94);
      END_STATE();
    case 266:
      if (lookahead == 'm') ADVANCE(46);
      END_STATE();
    case 267:
      if (lookahead == 'm') ADVANCE(175);
      END_STATE();
    case 268:
      if (lookahead == 'm') ADVANCE(179);
      END_STATE();
    case 269:
      if (lookahead == 'm') ADVANCE(338);
      END_STATE();
    case 270:
      if (lookahead == 'm') ADVANCE(403);
      if (lookahead == 's') ADVANCE(164);
      END_STATE();
    case 271:
      if (lookahead == 'm') ADVANCE(197);
      END_STATE();
    case 272:
      if (lookahead == 'm') ADVANCE(194);
      END_STATE();
    case 273:
      if (lookahead == 'n') ADVANCE(119);
      END_STATE();
    case 274:
      if (lookahead == 'n') ADVANCE(478);
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 275:
      if (lookahead == 'n') ADVANCE(548);
      END_STATE();
    case 276:
      if (lookahead == 'n') ADVANCE(545);
      END_STATE();
    case 277:
      if (lookahead == 'n') ADVANCE(564);
      END_STATE();
    case 278:
      if (lookahead == 'n') ADVANCE(127);
      END_STATE();
    case 279:
      if (lookahead == 'n') ADVANCE(453);
      END_STATE();
    case 280:
      if (lookahead == 'n') ADVANCE(428);
      END_STATE();
    case 281:
      if (lookahead == 'n') ADVANCE(77);
      END_STATE();
    case 282:
      if (lookahead == 'n') ADVANCE(383);
      END_STATE();
    case 283:
      if (lookahead == 'n') ADVANCE(92);
      END_STATE();
    case 284:
      if (lookahead == 'n') ADVANCE(434);
      END_STATE();
    case 285:
      if (lookahead == 'n') ADVANCE(55);
      END_STATE();
    case 286:
      if (lookahead == 'n') ADVANCE(47);
      END_STATE();
    case 287:
      if (lookahead == 'n') ADVANCE(445);
      END_STATE();
    case 288:
      if (lookahead == 'n') ADVANCE(447);
      if (lookahead == 'u') ADVANCE(290);
      END_STATE();
    case 289:
      if (lookahead == 'n') ADVANCE(53);
      END_STATE();
    case 290:
      if (lookahead == 'n') ADVANCE(439);
      END_STATE();
    case 291:
      if (lookahead == 'n') ADVANCE(24);
      END_STATE();
    case 292:
      if (lookahead == 'n') ADVANCE(420);
      END_STATE();
    case 293:
      if (lookahead == 'n') ADVANCE(421);
      END_STATE();
    case 294:
      if (lookahead == 'n') ADVANCE(150);
      END_STATE();
    case 295:
      if (lookahead == 'n') ADVANCE(237);
      END_STATE();
    case 296:
      if (lookahead == 'n') ADVANCE(440);
      END_STATE();
    case 297:
      if (lookahead == 'n') ADVANCE(196);
      END_STATE();
    case 298:
      if (lookahead == 'o') ADVANCE(288);
      END_STATE();
    case 299:
      if (lookahead == 'o') ADVANCE(251);
      END_STATE();
    case 300:
      if (lookahead == 'o') ADVANCE(264);
      END_STATE();
    case 301:
      if (lookahead == 'o') ADVANCE(348);
      END_STATE();
    case 302:
      if (lookahead == 'o') ADVANCE(391);
      END_STATE();
    case 303:
      if (lookahead == 'o') ADVANCE(241);
      END_STATE();
    case 304:
      if (lookahead == 'o') ADVANCE(339);
      END_STATE();
    case 305:
      if (lookahead == 'o') ADVANCE(415);
      END_STATE();
    case 306:
      if (lookahead == 'o') ADVANCE(299);
      END_STATE();
    case 307:
      if (lookahead == 'o') ADVANCE(276);
      END_STATE();
    case 308:
      if (lookahead == 'o') ADVANCE(353);
      END_STATE();
    case 309:
      if (lookahead == 'o') ADVANCE(122);
      END_STATE();
    case 310:
      if (lookahead == 'o') ADVANCE(294);
      END_STATE();
    case 311:
      if (lookahead == 'o') ADVANCE(277);
      END_STATE();
    case 312:
      if (lookahead == 'o') ADVANCE(291);
      END_STATE();
    case 313:
      if (lookahead == 'o') ADVANCE(419);
      END_STATE();
    case 314:
      if (lookahead == 'o') ADVANCE(376);
      END_STATE();
    case 315:
      if (lookahead == 'o') ADVANCE(352);
      END_STATE();
    case 316:
      if (lookahead == 'o') ADVANCE(423);
      END_STATE();
    case 317:
      if (lookahead == 'o') ADVANCE(250);
      END_STATE();
    case 318:
      if (lookahead == 'o') ADVANCE(51);
      END_STATE();
    case 319:
      if (lookahead == 'o') ADVANCE(394);
      END_STATE();
    case 320:
      if (lookahead == 'o') ADVANCE(130);
      END_STATE();
    case 321:
      if (lookahead == 'o') ADVANCE(286);
      END_STATE();
    case 322:
      if (lookahead == 'o') ADVANCE(399);
      END_STATE();
    case 323:
      if (lookahead == 'o') ADVANCE(131);
      END_STATE();
    case 324:
      if (lookahead == 'o') ADVANCE(374);
      END_STATE();
    case 325:
      if (lookahead == 'o') ADVANCE(375);
      END_STATE();
    case 326:
      if (lookahead == 'o') ADVANCE(132);
      END_STATE();
    case 327:
      if (lookahead == 'o') ADVANCE(133);
      END_STATE();
    case 328:
      if (lookahead == 'o') ADVANCE(379);
      END_STATE();
    case 329:
      if (lookahead == 'o') ADVANCE(252);
      END_STATE();
    case 330:
      if (lookahead == 'o') ADVANCE(329);
      END_STATE();
    case 331:
      if (lookahead == 'o') ADVANCE(67);
      END_STATE();
    case 332:
      if (lookahead == 'o') ADVANCE(68);
      END_STATE();
    case 333:
      if (lookahead == 'p') ADVANCE(534);
      END_STATE();
    case 334:
      if (lookahead == 'p') ADVANCE(10);
      END_STATE();
    case 335:
      if (lookahead == 'p') ADVANCE(11);
      END_STATE();
    case 336:
      if (lookahead == 'p') ADVANCE(34);
      END_STATE();
    case 337:
      if (lookahead == 'p') ADVANCE(87);
      END_STATE();
    case 338:
      if (lookahead == 'p') ADVANCE(16);
      END_STATE();
    case 339:
      if (lookahead == 'p') ADVANCE(177);
      END_STATE();
    case 340:
      if (lookahead == 'p') ADVANCE(89);
      if (lookahead == 'q') ADVANCE(461);
      END_STATE();
    case 341:
      if (lookahead == 'p') ADVANCE(90);
      if (lookahead == 'q') ADVANCE(462);
      END_STATE();
    case 342:
      if (lookahead == 'p') ADVANCE(400);
      END_STATE();
    case 343:
      if (lookahead == 'q') ADVANCE(487);
      END_STATE();
    case 344:
      if (lookahead == 'q') ADVANCE(257);
      END_STATE();
    case 345:
      if (lookahead == 'q') ADVANCE(463);
      END_STATE();
    case 346:
      if (lookahead == 'r') ADVANCE(483);
      END_STATE();
    case 347:
      if (lookahead == 'r') ADVANCE(450);
      END_STATE();
    case 348:
      if (lookahead == 'r') ADVANCE(481);
      END_STATE();
    case 349:
      if (lookahead == 'r') ADVANCE(249);
      END_STATE();
    case 350:
      if (lookahead == 'r') ADVANCE(467);
      END_STATE();
    case 351:
      if (lookahead == 'r') ADVANCE(537);
      END_STATE();
    case 352:
      if (lookahead == 'r') ADVANCE(546);
      END_STATE();
    case 353:
      if (lookahead == 'r') ADVANCE(469);
      END_STATE();
    case 354:
      if (lookahead == 'r') ADVANCE(102);
      END_STATE();
    case 355:
      if (lookahead == 'r') ADVANCE(471);
      END_STATE();
    case 356:
      if (lookahead == 'r') ADVANCE(472);
      END_STATE();
    case 357:
      if (lookahead == 'r') ADVANCE(473);
      END_STATE();
    case 358:
      if (lookahead == 'r') ADVANCE(129);
      END_STATE();
    case 359:
      if (lookahead == 'r') ADVANCE(108);
      if (lookahead == 's') ADVANCE(344);
      if (lookahead == 'x') ADVANCE(397);
      END_STATE();
    case 360:
      if (lookahead == 'r') ADVANCE(64);
      END_STATE();
    case 361:
      if (lookahead == 'r') ADVANCE(187);
      END_STATE();
    case 362:
      if (lookahead == 'r') ADVANCE(220);
      END_STATE();
    case 363:
      if (lookahead == 'r') ADVANCE(45);
      END_STATE();
    case 364:
      if (lookahead == 'r') ADVANCE(318);
      END_STATE();
    case 365:
      if (lookahead == 'r') ADVANCE(222);
      END_STATE();
    case 366:
      if (lookahead == 'r') ADVANCE(396);
      END_STATE();
    case 367:
      if (lookahead == 'r') ADVANCE(22);
      END_STATE();
    case 368:
      if (lookahead == 'r') ADVANCE(223);
      END_STATE();
    case 369:
      if (lookahead == 'r') ADVANCE(304);
      END_STATE();
    case 370:
      if (lookahead == 'r') ADVANCE(228);
      END_STATE();
    case 371:
      if (lookahead == 'r') ADVANCE(224);
      END_STATE();
    case 372:
      if (lookahead == 'r') ADVANCE(170);
      END_STATE();
    case 373:
      if (lookahead == 'r') ADVANCE(153);
      END_STATE();
    case 374:
      if (lookahead == 'r') ADVANCE(144);
      END_STATE();
    case 375:
      if (lookahead == 'r') ADVANCE(145);
      END_STATE();
    case 376:
      if (lookahead == 'r') ADVANCE(422);
      END_STATE();
    case 377:
      if (lookahead == 'r') ADVANCE(169);
      END_STATE();
    case 378:
      if (lookahead == 'r') ADVANCE(441);
      END_STATE();
    case 379:
      if (lookahead == 'r') ADVANCE(149);
      END_STATE();
    case 380:
      if (lookahead == 'r') ADVANCE(154);
      if (lookahead == 'v') ADVANCE(198);
      END_STATE();
    case 381:
      if (lookahead == 'r') ADVANCE(245);
      END_STATE();
    case 382:
      if (lookahead == 's') ADVANCE(500);
      END_STATE();
    case 383:
      if (lookahead == 's') ADVANCE(499);
      END_STATE();
    case 384:
      if (lookahead == 's') ADVANCE(531);
      END_STATE();
    case 385:
      if (lookahead == 's') ADVANCE(540);
      END_STATE();
    case 386:
      if (lookahead == 's') ADVANCE(253);
      END_STATE();
    case 387:
      if (lookahead == 's') ADVANCE(141);
      END_STATE();
    case 388:
      if (lookahead == 's') ADVANCE(50);
      END_STATE();
    case 389:
      if (lookahead == 's') ADVANCE(111);
      END_STATE();
    case 390:
      if (lookahead == 's') ADVANCE(279);
      END_STATE();
    case 391:
      if (lookahead == 's') ADVANCE(426);
      END_STATE();
    case 392:
      if (lookahead == 's') ADVANCE(56);
      END_STATE();
    case 393:
      if (lookahead == 's') ADVANCE(213);
      END_STATE();
    case 394:
      if (lookahead == 's') ADVANCE(416);
      END_STATE();
    case 395:
      if (lookahead == 's') ADVANCE(162);
      END_STATE();
    case 396:
      if (lookahead == 's') ADVANCE(233);
      END_STATE();
    case 397:
      if (lookahead == 's') ADVANCE(384);
      END_STATE();
    case 398:
      if (lookahead == 's') ADVANCE(166);
      END_STATE();
    case 399:
      if (lookahead == 's') ADVANCE(443);
      END_STATE();
    case 400:
      if (lookahead == 's') ADVANCE(449);
      END_STATE();
    case 401:
      if (lookahead == 's') ADVANCE(181);
      END_STATE();
    case 402:
      if (lookahead == 's') ADVANCE(436);
      END_STATE();
    case 403:
      if (lookahead == 's') ADVANCE(165);
      END_STATE();
    case 404:
      if (lookahead == 's') ADVANCE(174);
      END_STATE();
    case 405:
      if (lookahead == 's') ADVANCE(437);
      END_STATE();
    case 406:
      if (lookahead == 's') ADVANCE(234);
      END_STATE();
    case 407:
      if (lookahead == 's') ADVANCE(438);
      END_STATE();
    case 408:
      if (lookahead == 's') ADVANCE(404);
      END_STATE();
    case 409:
      if (lookahead == 's') ADVANCE(113);
      END_STATE();
    case 410:
      if (lookahead == 's') ADVANCE(331);
      END_STATE();
    case 411:
      if (lookahead == 's') ADVANCE(332);
      END_STATE();
    case 412:
      if (lookahead == 't') ADVANCE(334);
      END_STATE();
    case 413:
      if (lookahead == 't') ADVANCE(101);
      END_STATE();
    case 414:
      if (lookahead == 't') ADVANCE(521);
      END_STATE();
    case 415:
      if (lookahead == 't') ADVANCE(44);
      END_STATE();
    case 416:
      if (lookahead == 't') ADVANCE(536);
      END_STATE();
    case 417:
      if (lookahead == 't') ADVANCE(470);
      END_STATE();
    case 418:
      if (lookahead == 't') ADVANCE(547);
      END_STATE();
    case 419:
      if (lookahead == 't') ADVANCE(568);
      END_STATE();
    case 420:
      if (lookahead == 't') ADVANCE(544);
      END_STATE();
    case 421:
      if (lookahead == 't') ADVANCE(552);
      END_STATE();
    case 422:
      if (lookahead == 't') ADVANCE(527);
      END_STATE();
    case 423:
      if (lookahead == 't') ADVANCE(566);
      END_STATE();
    case 424:
      if (lookahead == 't') ADVANCE(412);
      END_STATE();
    case 425:
      if (lookahead == 't') ADVANCE(216);
      END_STATE();
    case 426:
      if (lookahead == 't') ADVANCE(281);
      END_STATE();
    case 427:
      if (lookahead == 't') ADVANCE(218);
      END_STATE();
    case 428:
      if (lookahead == 't') ADVANCE(75);
      END_STATE();
    case 429:
      if (lookahead == 't') ADVANCE(211);
      END_STATE();
    case 430:
      if (lookahead == 't') ADVANCE(66);
      END_STATE();
    case 431:
      if (lookahead == 't') ADVANCE(212);
      END_STATE();
    case 432:
      if (lookahead == 't') ADVANCE(82);
      END_STATE();
    case 433:
      if (lookahead == 't') ADVANCE(364);
      END_STATE();
    case 434:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 435:
      if (lookahead == 't') ADVANCE(74);
      END_STATE();
    case 436:
      if (lookahead == 't') ADVANCE(79);
      END_STATE();
    case 437:
      if (lookahead == 't') ADVANCE(13);
      END_STATE();
    case 438:
      if (lookahead == 't') ADVANCE(14);
      END_STATE();
    case 439:
      if (lookahead == 't') ADVANCE(355);
      END_STATE();
    case 440:
      if (lookahead == 't') ADVANCE(15);
      END_STATE();
    case 441:
      if (lookahead == 't') ADVANCE(48);
      END_STATE();
    case 442:
      if (lookahead == 't') ADVANCE(161);
      END_STATE();
    case 443:
      if (lookahead == 't') ADVANCE(78);
      END_STATE();
    case 444:
      if (lookahead == 't') ADVANCE(446);
      END_STATE();
    case 445:
      if (lookahead == 't') ADVANCE(54);
      END_STATE();
    case 446:
      if (lookahead == 't') ADVANCE(336);
      END_STATE();
    case 447:
      if (lookahead == 't') ADVANCE(231);
      END_STATE();
    case 448:
      if (lookahead == 't') ADVANCE(238);
      END_STATE();
    case 449:
      if (lookahead == 't') ADVANCE(377);
      END_STATE();
    case 450:
      if (lookahead == 'u') ADVANCE(140);
      END_STATE();
    case 451:
      if (lookahead == 'u') ADVANCE(342);
      END_STATE();
    case 452:
      if (lookahead == 'u') ADVANCE(98);
      END_STATE();
    case 453:
      if (lookahead == 'u') ADVANCE(263);
      END_STATE();
    case 454:
      if (lookahead == 'u') ADVANCE(256);
      END_STATE();
    case 455:
      if (lookahead == 'u') ADVANCE(295);
      END_STATE();
    case 456:
      if (lookahead == 'u') ADVANCE(192);
      END_STATE();
    case 457:
      if (lookahead == 'u') ADVANCE(369);
      END_STATE();
    case 458:
      if (lookahead == 'u') ADVANCE(368);
      END_STATE();
    case 459:
      if (lookahead == 'u') ADVANCE(427);
      END_STATE();
    case 460:
      if (lookahead == 'u') ADVANCE(371);
      END_STATE();
    case 461:
      if (lookahead == 'u') ADVANCE(183);
      END_STATE();
    case 462:
      if (lookahead == 'u') ADVANCE(184);
      END_STATE();
    case 463:
      if (lookahead == 'u') ADVANCE(195);
      END_STATE();
    case 464:
      if (lookahead == 'u') ADVANCE(261);
      END_STATE();
    case 465:
      if (lookahead == 'v') ADVANCE(243);
      END_STATE();
    case 466:
      if (lookahead == 'v') ADVANCE(317);
      END_STATE();
    case 467:
      if (lookahead == 'v') ADVANCE(176);
      END_STATE();
    case 468:
      if (lookahead == 'w') ADVANCE(23);
      END_STATE();
    case 469:
      if (lookahead == 'w') ADVANCE(85);
      END_STATE();
    case 470:
      if (lookahead == 'y') ADVANCE(549);
      END_STATE();
    case 471:
      if (lookahead == 'y') ADVANCE(553);
      END_STATE();
    case 472:
      if (lookahead == 'y') ADVANCE(543);
      END_STATE();
    case 473:
      if (lookahead == 'y') ADVANCE(559);
      END_STATE();
    case 474:
      if (lookahead == 'z') ADVANCE(310);
      END_STATE();
    case 475:
      if (lookahead == '|') ADVANCE(484);
      END_STATE();
    case 476:
      if (lookahead == '}') ADVANCE(486);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(476)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(509);
      END_STATE();
    case 477:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 478:
      ACCEPT_TOKEN(anon_sym_in);
      END_STATE();
    case 479:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 480:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 481:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 482:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 483:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 484:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 485:
      ACCEPT_TOKEN(anon_sym_LBRACE);
      END_STATE();
    case 486:
      ACCEPT_TOKEN(anon_sym_RBRACE);
      END_STATE();
    case 487:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 488:
      ACCEPT_TOKEN(anon_sym_ne);
      END_STATE();
    case 489:
      ACCEPT_TOKEN(anon_sym_lt);
      END_STATE();
    case 490:
      ACCEPT_TOKEN(anon_sym_le);
      END_STATE();
    case 491:
      ACCEPT_TOKEN(anon_sym_gt);
      END_STATE();
    case 492:
      ACCEPT_TOKEN(anon_sym_ge);
      END_STATE();
    case 493:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 494:
      ACCEPT_TOKEN(anon_sym_BANG_EQ);
      END_STATE();
    case 495:
      ACCEPT_TOKEN(anon_sym_LT);
      if (lookahead == '=') ADVANCE(496);
      END_STATE();
    case 496:
      ACCEPT_TOKEN(anon_sym_LT_EQ);
      END_STATE();
    case 497:
      ACCEPT_TOKEN(anon_sym_GT);
      if (lookahead == '=') ADVANCE(498);
      END_STATE();
    case 498:
      ACCEPT_TOKEN(anon_sym_GT_EQ);
      END_STATE();
    case 499:
      ACCEPT_TOKEN(anon_sym_contains);
      END_STATE();
    case 500:
      ACCEPT_TOKEN(anon_sym_matches);
      END_STATE();
    case 501:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 502:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 503:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 504:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(36);
      if (lookahead == '5') ADVANCE(505);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(506);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(507);
      END_STATE();
    case 505:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(36);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(509);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(506);
      END_STATE();
    case 506:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(36);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(509);
      END_STATE();
    case 507:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(36);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(506);
      END_STATE();
    case 508:
      ACCEPT_TOKEN(sym_number);
      if (lookahead == '.') ADVANCE(36);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(507);
      END_STATE();
    case 509:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(509);
      END_STATE();
    case 510:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '/') ADVANCE(40);
      END_STATE();
    case 511:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '/') ADVANCE(40);
      if (lookahead == '5') ADVANCE(512);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(510);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(513);
      END_STATE();
    case 512:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '/') ADVANCE(40);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(510);
      END_STATE();
    case 513:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '/') ADVANCE(40);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(510);
      END_STATE();
    case 514:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '/') ADVANCE(40);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(513);
      END_STATE();
    case 515:
      ACCEPT_TOKEN(sym_ip_range);
      END_STATE();
    case 516:
      ACCEPT_TOKEN(sym_ip_range);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(515);
      END_STATE();
    case 517:
      ACCEPT_TOKEN(sym_ip_range);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(515);
      END_STATE();
    case 518:
      ACCEPT_TOKEN(sym_string);
      if (lookahead == '"') ADVANCE(518);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(1);
      END_STATE();
    case 519:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 520:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 521:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 522:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(494);
      END_STATE();
    case 523:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 524:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 525:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 526:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 527:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 528:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 529:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(359);
      END_STATE();
    case 530:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 531:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 532:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 533:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(105);
      END_STATE();
    case 534:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 535:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 536:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 537:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 538:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 539:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 540:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 541:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(340);
      END_STATE();
    case 542:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 543:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 544:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 545:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 546:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 547:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 548:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 549:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 550:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 551:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 552:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 553:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 554:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 555:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 556:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 557:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(341);
      END_STATE();
    case 558:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 559:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 560:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 561:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 562:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 563:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 564:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 565:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 566:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 567:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 568:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 569:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 570:
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
  [7] = {.lex_state = 0},
  [8] = {.lex_state = 0},
  [9] = {.lex_state = 0},
  [10] = {.lex_state = 0},
  [11] = {.lex_state = 0},
  [12] = {.lex_state = 0},
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
  [29] = {.lex_state = 39},
  [30] = {.lex_state = 39},
  [31] = {.lex_state = 0},
  [32] = {.lex_state = 0},
  [33] = {.lex_state = 39},
  [34] = {.lex_state = 0},
  [35] = {.lex_state = 476},
  [36] = {.lex_state = 0},
  [37] = {.lex_state = 39},
  [38] = {.lex_state = 476},
  [39] = {.lex_state = 0},
  [40] = {.lex_state = 476},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 476},
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
    [sym_ipv4] = ACTIONS(1),
    [sym_ip_range] = ACTIONS(1),
    [sym_string] = ACTIONS(1),
    [anon_sym_true] = ACTIONS(1),
    [anon_sym_false] = ACTIONS(1),
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
    [sym_source_file] = STATE(45),
    [sym__expression] = STATE(22),
    [sym_not_expression] = STATE(22),
    [sym_in_expression] = STATE(22),
    [sym_compound_expression] = STATE(22),
    [sym_simple_expression] = STATE(22),
    [sym_group] = STATE(22),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(3),
    [anon_sym_LPAREN] = ACTIONS(5),
    [anon_sym_not] = ACTIONS(7),
    [anon_sym_BANG] = ACTIONS(7),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(9),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(9),
    [anon_sym_ip_DOTsrc] = ACTIONS(13),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(15),
    [anon_sym_http_DOTcookie] = ACTIONS(17),
    [anon_sym_http_DOThost] = ACTIONS(17),
    [anon_sym_http_DOTreferer] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_http_DOTuser_agent] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(17),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(17),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(17),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(21),
    [anon_sym_ssl] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(21),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(21),
  },
  [2] = {
    [sym__expression] = STATE(22),
    [sym_not_expression] = STATE(22),
    [sym_in_expression] = STATE(22),
    [sym_compound_expression] = STATE(22),
    [sym_simple_expression] = STATE(22),
    [sym_group] = STATE(22),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(23),
    [anon_sym_LPAREN] = ACTIONS(5),
    [anon_sym_not] = ACTIONS(7),
    [anon_sym_BANG] = ACTIONS(7),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(9),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(9),
    [anon_sym_ip_DOTsrc] = ACTIONS(13),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(15),
    [anon_sym_http_DOTcookie] = ACTIONS(17),
    [anon_sym_http_DOThost] = ACTIONS(17),
    [anon_sym_http_DOTreferer] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_http_DOTuser_agent] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(17),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(17),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(17),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(21),
    [anon_sym_ssl] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(21),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(21),
  },
  [3] = {
    [sym__expression] = STATE(22),
    [sym_not_expression] = STATE(22),
    [sym_in_expression] = STATE(22),
    [sym_compound_expression] = STATE(22),
    [sym_simple_expression] = STATE(22),
    [sym_group] = STATE(22),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [aux_sym_source_file_repeat1] = STATE(3),
    [ts_builtin_sym_end] = ACTIONS(25),
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
  [4] = {
    [ts_builtin_sym_end] = ACTIONS(54),
    [anon_sym_AMP_AMP] = ACTIONS(54),
    [anon_sym_and] = ACTIONS(54),
    [anon_sym_xor] = ACTIONS(54),
    [anon_sym_CARET_CARET] = ACTIONS(54),
    [anon_sym_or] = ACTIONS(54),
    [anon_sym_PIPE_PIPE] = ACTIONS(54),
    [anon_sym_eq] = ACTIONS(56),
    [anon_sym_ne] = ACTIONS(56),
    [anon_sym_EQ_EQ] = ACTIONS(56),
    [anon_sym_BANG_EQ] = ACTIONS(56),
    [anon_sym_LPAREN] = ACTIONS(54),
    [anon_sym_RPAREN] = ACTIONS(54),
    [anon_sym_not] = ACTIONS(54),
    [anon_sym_BANG] = ACTIONS(58),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(54),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(54),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(54),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(54),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(54),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(54),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(58),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(54),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(54),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(54),
    [anon_sym_ip_DOTsrc] = ACTIONS(58),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(54),
    [anon_sym_http_DOTcookie] = ACTIONS(54),
    [anon_sym_http_DOThost] = ACTIONS(54),
    [anon_sym_http_DOTreferer] = ACTIONS(54),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(54),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(54),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(54),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(58),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(54),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(54),
    [anon_sym_http_DOTuser_agent] = ACTIONS(54),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(54),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(54),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(54),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(54),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(54),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(54),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(54),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(54),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(54),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(54),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(54),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(54),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(58),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(54),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(54),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(54),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(54),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(54),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(54),
    [anon_sym_ssl] = ACTIONS(54),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(54),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(54),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(54),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(54),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(54),
  },
  [5] = {
    [ts_builtin_sym_end] = ACTIONS(60),
    [anon_sym_AMP_AMP] = ACTIONS(60),
    [anon_sym_and] = ACTIONS(60),
    [anon_sym_xor] = ACTIONS(60),
    [anon_sym_CARET_CARET] = ACTIONS(60),
    [anon_sym_or] = ACTIONS(60),
    [anon_sym_PIPE_PIPE] = ACTIONS(60),
    [anon_sym_eq] = ACTIONS(60),
    [anon_sym_ne] = ACTIONS(60),
    [anon_sym_EQ_EQ] = ACTIONS(60),
    [anon_sym_BANG_EQ] = ACTIONS(60),
    [anon_sym_LPAREN] = ACTIONS(60),
    [anon_sym_RPAREN] = ACTIONS(60),
    [anon_sym_not] = ACTIONS(60),
    [anon_sym_BANG] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(60),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(60),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(60),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(60),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(60),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(62),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(60),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(60),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(60),
    [anon_sym_ip_DOTsrc] = ACTIONS(62),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(60),
    [anon_sym_http_DOTcookie] = ACTIONS(60),
    [anon_sym_http_DOThost] = ACTIONS(60),
    [anon_sym_http_DOTreferer] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(62),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(60),
    [anon_sym_http_DOTuser_agent] = ACTIONS(60),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(60),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(60),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(60),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(60),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(60),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(60),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(60),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(60),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(60),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(60),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(60),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(60),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(62),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(60),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(60),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(60),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(60),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(60),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(60),
    [anon_sym_ssl] = ACTIONS(60),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(60),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(60),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(60),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(60),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(60),
  },
  [6] = {
    [sym__expression] = STATE(28),
    [sym_not_expression] = STATE(28),
    [sym_in_expression] = STATE(28),
    [sym_compound_expression] = STATE(28),
    [sym_simple_expression] = STATE(28),
    [sym_group] = STATE(28),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [anon_sym_LPAREN] = ACTIONS(5),
    [anon_sym_not] = ACTIONS(7),
    [anon_sym_BANG] = ACTIONS(7),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(9),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(9),
    [anon_sym_ip_DOTsrc] = ACTIONS(13),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(15),
    [anon_sym_http_DOTcookie] = ACTIONS(17),
    [anon_sym_http_DOThost] = ACTIONS(17),
    [anon_sym_http_DOTreferer] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_http_DOTuser_agent] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(17),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(17),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(17),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(21),
    [anon_sym_ssl] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(21),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(21),
  },
  [7] = {
    [sym__expression] = STATE(21),
    [sym_not_expression] = STATE(21),
    [sym_in_expression] = STATE(21),
    [sym_compound_expression] = STATE(21),
    [sym_simple_expression] = STATE(21),
    [sym_group] = STATE(21),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [anon_sym_LPAREN] = ACTIONS(5),
    [anon_sym_not] = ACTIONS(7),
    [anon_sym_BANG] = ACTIONS(7),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(9),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(9),
    [anon_sym_ip_DOTsrc] = ACTIONS(13),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(15),
    [anon_sym_http_DOTcookie] = ACTIONS(17),
    [anon_sym_http_DOThost] = ACTIONS(17),
    [anon_sym_http_DOTreferer] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_http_DOTuser_agent] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(17),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(17),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(17),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(21),
    [anon_sym_ssl] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(21),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(21),
  },
  [8] = {
    [sym__expression] = STATE(13),
    [sym_not_expression] = STATE(13),
    [sym_in_expression] = STATE(13),
    [sym_compound_expression] = STATE(13),
    [sym_simple_expression] = STATE(13),
    [sym_group] = STATE(13),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [anon_sym_LPAREN] = ACTIONS(5),
    [anon_sym_not] = ACTIONS(7),
    [anon_sym_BANG] = ACTIONS(7),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(9),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(9),
    [anon_sym_ip_DOTsrc] = ACTIONS(13),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(15),
    [anon_sym_http_DOTcookie] = ACTIONS(17),
    [anon_sym_http_DOThost] = ACTIONS(17),
    [anon_sym_http_DOTreferer] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_http_DOTuser_agent] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(17),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(17),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(17),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(21),
    [anon_sym_ssl] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(21),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(21),
  },
  [9] = {
    [sym__expression] = STATE(12),
    [sym_not_expression] = STATE(12),
    [sym_in_expression] = STATE(12),
    [sym_compound_expression] = STATE(12),
    [sym_simple_expression] = STATE(12),
    [sym_group] = STATE(12),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [anon_sym_LPAREN] = ACTIONS(5),
    [anon_sym_not] = ACTIONS(7),
    [anon_sym_BANG] = ACTIONS(7),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(9),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(9),
    [anon_sym_ip_DOTsrc] = ACTIONS(13),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(15),
    [anon_sym_http_DOTcookie] = ACTIONS(17),
    [anon_sym_http_DOThost] = ACTIONS(17),
    [anon_sym_http_DOTreferer] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_http_DOTuser_agent] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(17),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(17),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(17),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(21),
    [anon_sym_ssl] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(21),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(21),
  },
  [10] = {
    [sym__expression] = STATE(18),
    [sym_not_expression] = STATE(18),
    [sym_in_expression] = STATE(18),
    [sym_compound_expression] = STATE(18),
    [sym_simple_expression] = STATE(18),
    [sym_group] = STATE(18),
    [sym_not_operator] = STATE(10),
    [sym_number_field] = STATE(26),
    [sym_ip_field] = STATE(32),
    [sym_string_field] = STATE(24),
    [sym_boolean_field] = STATE(4),
    [anon_sym_LPAREN] = ACTIONS(5),
    [anon_sym_not] = ACTIONS(7),
    [anon_sym_BANG] = ACTIONS(7),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(9),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(9),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(9),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(9),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(9),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(11),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(9),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(9),
    [anon_sym_ip_DOTsrc] = ACTIONS(13),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(15),
    [anon_sym_http_DOTcookie] = ACTIONS(17),
    [anon_sym_http_DOThost] = ACTIONS(17),
    [anon_sym_http_DOTreferer] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_http_DOTuser_agent] = ACTIONS(17),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(17),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(17),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(19),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(17),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(17),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(17),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(17),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(17),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(21),
    [anon_sym_ssl] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(21),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(21),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(21),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(21),
  },
  [11] = {
    [ts_builtin_sym_end] = ACTIONS(64),
    [anon_sym_AMP_AMP] = ACTIONS(64),
    [anon_sym_and] = ACTIONS(64),
    [anon_sym_xor] = ACTIONS(64),
    [anon_sym_CARET_CARET] = ACTIONS(64),
    [anon_sym_or] = ACTIONS(64),
    [anon_sym_PIPE_PIPE] = ACTIONS(64),
    [anon_sym_LPAREN] = ACTIONS(64),
    [anon_sym_RPAREN] = ACTIONS(64),
    [anon_sym_not] = ACTIONS(64),
    [anon_sym_BANG] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(64),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(64),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(64),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(64),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(64),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(66),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(64),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(64),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(64),
    [anon_sym_ip_DOTsrc] = ACTIONS(66),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(64),
    [anon_sym_http_DOTcookie] = ACTIONS(64),
    [anon_sym_http_DOThost] = ACTIONS(64),
    [anon_sym_http_DOTreferer] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(66),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(64),
    [anon_sym_http_DOTuser_agent] = ACTIONS(64),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(64),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(64),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(64),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(64),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(64),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(64),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(64),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(64),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(64),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(64),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(64),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(64),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(66),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(64),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(64),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(64),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(64),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(64),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(64),
    [anon_sym_ssl] = ACTIONS(64),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(64),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(64),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(64),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(64),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(64),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(68),
    [anon_sym_AMP_AMP] = ACTIONS(70),
    [anon_sym_and] = ACTIONS(70),
    [anon_sym_xor] = ACTIONS(72),
    [anon_sym_CARET_CARET] = ACTIONS(72),
    [anon_sym_or] = ACTIONS(68),
    [anon_sym_PIPE_PIPE] = ACTIONS(68),
    [anon_sym_LPAREN] = ACTIONS(68),
    [anon_sym_RPAREN] = ACTIONS(68),
    [anon_sym_not] = ACTIONS(68),
    [anon_sym_BANG] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(68),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(68),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(74),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(68),
    [anon_sym_ip_DOTsrc] = ACTIONS(74),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(68),
    [anon_sym_http_DOTcookie] = ACTIONS(68),
    [anon_sym_http_DOThost] = ACTIONS(68),
    [anon_sym_http_DOTreferer] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(68),
    [anon_sym_http_DOTuser_agent] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(68),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(68),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(68),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(68),
    [anon_sym_ssl] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(68),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(68),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(68),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(68),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(68),
    [anon_sym_AMP_AMP] = ACTIONS(70),
    [anon_sym_and] = ACTIONS(70),
    [anon_sym_xor] = ACTIONS(68),
    [anon_sym_CARET_CARET] = ACTIONS(68),
    [anon_sym_or] = ACTIONS(68),
    [anon_sym_PIPE_PIPE] = ACTIONS(68),
    [anon_sym_LPAREN] = ACTIONS(68),
    [anon_sym_RPAREN] = ACTIONS(68),
    [anon_sym_not] = ACTIONS(68),
    [anon_sym_BANG] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(68),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(68),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(74),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(68),
    [anon_sym_ip_DOTsrc] = ACTIONS(74),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(68),
    [anon_sym_http_DOTcookie] = ACTIONS(68),
    [anon_sym_http_DOThost] = ACTIONS(68),
    [anon_sym_http_DOTreferer] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(68),
    [anon_sym_http_DOTuser_agent] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(68),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(68),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(68),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(68),
    [anon_sym_ssl] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(68),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(68),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(68),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(68),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(76),
    [anon_sym_AMP_AMP] = ACTIONS(76),
    [anon_sym_and] = ACTIONS(76),
    [anon_sym_xor] = ACTIONS(76),
    [anon_sym_CARET_CARET] = ACTIONS(76),
    [anon_sym_or] = ACTIONS(76),
    [anon_sym_PIPE_PIPE] = ACTIONS(76),
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
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(80),
    [anon_sym_AMP_AMP] = ACTIONS(80),
    [anon_sym_and] = ACTIONS(80),
    [anon_sym_xor] = ACTIONS(80),
    [anon_sym_CARET_CARET] = ACTIONS(80),
    [anon_sym_or] = ACTIONS(80),
    [anon_sym_PIPE_PIPE] = ACTIONS(80),
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
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(84),
    [anon_sym_AMP_AMP] = ACTIONS(84),
    [anon_sym_and] = ACTIONS(84),
    [anon_sym_xor] = ACTIONS(84),
    [anon_sym_CARET_CARET] = ACTIONS(84),
    [anon_sym_or] = ACTIONS(84),
    [anon_sym_PIPE_PIPE] = ACTIONS(84),
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
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(88),
    [anon_sym_AMP_AMP] = ACTIONS(88),
    [anon_sym_and] = ACTIONS(88),
    [anon_sym_xor] = ACTIONS(88),
    [anon_sym_CARET_CARET] = ACTIONS(88),
    [anon_sym_or] = ACTIONS(88),
    [anon_sym_PIPE_PIPE] = ACTIONS(88),
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
  [18] = {
    [ts_builtin_sym_end] = ACTIONS(92),
    [anon_sym_AMP_AMP] = ACTIONS(92),
    [anon_sym_and] = ACTIONS(92),
    [anon_sym_xor] = ACTIONS(92),
    [anon_sym_CARET_CARET] = ACTIONS(92),
    [anon_sym_or] = ACTIONS(92),
    [anon_sym_PIPE_PIPE] = ACTIONS(92),
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
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(96),
    [anon_sym_AMP_AMP] = ACTIONS(96),
    [anon_sym_and] = ACTIONS(96),
    [anon_sym_xor] = ACTIONS(96),
    [anon_sym_CARET_CARET] = ACTIONS(96),
    [anon_sym_or] = ACTIONS(96),
    [anon_sym_PIPE_PIPE] = ACTIONS(96),
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
  [20] = {
    [ts_builtin_sym_end] = ACTIONS(100),
    [anon_sym_AMP_AMP] = ACTIONS(100),
    [anon_sym_and] = ACTIONS(100),
    [anon_sym_xor] = ACTIONS(100),
    [anon_sym_CARET_CARET] = ACTIONS(100),
    [anon_sym_or] = ACTIONS(100),
    [anon_sym_PIPE_PIPE] = ACTIONS(100),
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
  [21] = {
    [ts_builtin_sym_end] = ACTIONS(68),
    [anon_sym_AMP_AMP] = ACTIONS(68),
    [anon_sym_and] = ACTIONS(68),
    [anon_sym_xor] = ACTIONS(68),
    [anon_sym_CARET_CARET] = ACTIONS(68),
    [anon_sym_or] = ACTIONS(68),
    [anon_sym_PIPE_PIPE] = ACTIONS(68),
    [anon_sym_LPAREN] = ACTIONS(68),
    [anon_sym_RPAREN] = ACTIONS(68),
    [anon_sym_not] = ACTIONS(68),
    [anon_sym_BANG] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(68),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(68),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(74),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(68),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(68),
    [anon_sym_ip_DOTsrc] = ACTIONS(74),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(68),
    [anon_sym_http_DOTcookie] = ACTIONS(68),
    [anon_sym_http_DOThost] = ACTIONS(68),
    [anon_sym_http_DOTreferer] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(68),
    [anon_sym_http_DOTuser_agent] = ACTIONS(68),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(68),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(68),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(74),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(68),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(68),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(68),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(68),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(68),
    [anon_sym_ssl] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(68),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(68),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(68),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(68),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(68),
  },
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(104),
    [anon_sym_AMP_AMP] = ACTIONS(70),
    [anon_sym_and] = ACTIONS(70),
    [anon_sym_xor] = ACTIONS(72),
    [anon_sym_CARET_CARET] = ACTIONS(72),
    [anon_sym_or] = ACTIONS(106),
    [anon_sym_PIPE_PIPE] = ACTIONS(106),
    [anon_sym_LPAREN] = ACTIONS(104),
    [anon_sym_not] = ACTIONS(104),
    [anon_sym_BANG] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(104),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(104),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(104),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(104),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(108),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(104),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(104),
    [anon_sym_ip_DOTsrc] = ACTIONS(108),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(104),
    [anon_sym_http_DOTcookie] = ACTIONS(104),
    [anon_sym_http_DOThost] = ACTIONS(104),
    [anon_sym_http_DOTreferer] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(104),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(108),
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
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(108),
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
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 2,
    ACTIONS(112), 4,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_ip_DOTsrc,
      anon_sym_http_DOTrequest_DOTuri,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri,
    ACTIONS(110), 46,
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
  [55] = 3,
    ACTIONS(114), 1,
      anon_sym_in,
    ACTIONS(118), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(116), 13,
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
  [78] = 2,
    ACTIONS(122), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(120), 14,
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
  [99] = 3,
    ACTIONS(124), 1,
      anon_sym_in,
    ACTIONS(128), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(126), 10,
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
  [119] = 2,
    ACTIONS(132), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(130), 11,
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
  [137] = 4,
    ACTIONS(134), 1,
      anon_sym_RPAREN,
    ACTIONS(70), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(72), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(106), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [153] = 4,
    ACTIONS(136), 1,
      anon_sym_RBRACE,
    ACTIONS(138), 1,
      sym_ipv4,
    ACTIONS(141), 1,
      sym_ip_range,
    STATE(29), 2,
      sym__ip,
      aux_sym_ip_set_repeat1,
  [167] = 4,
    ACTIONS(144), 1,
      anon_sym_RBRACE,
    ACTIONS(146), 1,
      sym_ipv4,
    ACTIONS(148), 1,
      sym_ip_range,
    STATE(29), 2,
      sym__ip,
      aux_sym_ip_set_repeat1,
  [181] = 1,
    ACTIONS(150), 5,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [189] = 2,
    ACTIONS(152), 1,
      anon_sym_in,
    ACTIONS(154), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [199] = 3,
    ACTIONS(156), 1,
      sym_ipv4,
    ACTIONS(158), 1,
      sym_ip_range,
    STATE(30), 2,
      sym__ip,
      aux_sym_ip_set_repeat1,
  [210] = 2,
    STATE(17), 1,
      sym_boolean,
    ACTIONS(160), 2,
      anon_sym_true,
      anon_sym_false,
  [218] = 3,
    ACTIONS(162), 1,
      anon_sym_RBRACE,
    ACTIONS(164), 1,
      sym_number,
    STATE(38), 1,
      aux_sym_number_set_repeat1,
  [228] = 3,
    ACTIONS(166), 1,
      anon_sym_RBRACE,
    ACTIONS(168), 1,
      sym_string,
    STATE(39), 1,
      aux_sym_string_set_repeat1,
  [238] = 3,
    ACTIONS(170), 1,
      sym_ipv4,
    ACTIONS(172), 1,
      sym_ip_range,
    STATE(17), 1,
      sym__ip,
  [248] = 3,
    ACTIONS(174), 1,
      anon_sym_RBRACE,
    ACTIONS(176), 1,
      sym_number,
    STATE(38), 1,
      aux_sym_number_set_repeat1,
  [258] = 3,
    ACTIONS(179), 1,
      anon_sym_RBRACE,
    ACTIONS(181), 1,
      sym_string,
    STATE(39), 1,
      aux_sym_string_set_repeat1,
  [268] = 2,
    ACTIONS(184), 1,
      sym_number,
    STATE(35), 1,
      aux_sym_number_set_repeat1,
  [275] = 2,
    ACTIONS(186), 1,
      sym_string,
    STATE(36), 1,
      aux_sym_string_set_repeat1,
  [282] = 2,
    ACTIONS(188), 1,
      anon_sym_LBRACE,
    STATE(14), 1,
      sym_string_set,
  [289] = 2,
    ACTIONS(190), 1,
      anon_sym_LBRACE,
    STATE(14), 1,
      sym_ip_set,
  [296] = 2,
    ACTIONS(192), 1,
      anon_sym_LBRACE,
    STATE(14), 1,
      sym_number_set,
  [303] = 1,
    ACTIONS(194), 1,
      ts_builtin_sym_end,
  [307] = 1,
    ACTIONS(172), 1,
      sym_string,
  [311] = 1,
    ACTIONS(172), 1,
      sym_number,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(23)] = 0,
  [SMALL_STATE(24)] = 55,
  [SMALL_STATE(25)] = 78,
  [SMALL_STATE(26)] = 99,
  [SMALL_STATE(27)] = 119,
  [SMALL_STATE(28)] = 137,
  [SMALL_STATE(29)] = 153,
  [SMALL_STATE(30)] = 167,
  [SMALL_STATE(31)] = 181,
  [SMALL_STATE(32)] = 189,
  [SMALL_STATE(33)] = 199,
  [SMALL_STATE(34)] = 210,
  [SMALL_STATE(35)] = 218,
  [SMALL_STATE(36)] = 228,
  [SMALL_STATE(37)] = 238,
  [SMALL_STATE(38)] = 248,
  [SMALL_STATE(39)] = 258,
  [SMALL_STATE(40)] = 268,
  [SMALL_STATE(41)] = 275,
  [SMALL_STATE(42)] = 282,
  [SMALL_STATE(43)] = 289,
  [SMALL_STATE(44)] = 296,
  [SMALL_STATE(45)] = 303,
  [SMALL_STATE(46)] = 307,
  [SMALL_STATE(47)] = 311,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [5] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [11] = {.entry = {.count = 1, .reusable = false}}, SHIFT(27),
  [13] = {.entry = {.count = 1, .reusable = false}}, SHIFT(31),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [19] = {.entry = {.count = 1, .reusable = false}}, SHIFT(25),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [23] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [25] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [27] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(6),
  [30] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(23),
  [33] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(27),
  [36] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(27),
  [39] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(31),
  [42] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(31),
  [45] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(25),
  [48] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(25),
  [51] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(5),
  [54] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__expression, 1),
  [56] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [58] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__expression, 1),
  [60] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean_field, 1),
  [62] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean_field, 1),
  [64] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [66] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [68] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 1),
  [70] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [72] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [74] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 1),
  [76] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [78] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [80] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [82] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [84] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3),
  [86] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3),
  [88] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [90] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [92] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [94] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [96] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [98] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [100] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [102] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [104] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [106] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [108] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [110] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [112] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [114] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [116] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [118] = {.entry = {.count = 1, .reusable = false}}, SHIFT(46),
  [120] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [122] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [124] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [126] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [128] = {.entry = {.count = 1, .reusable = false}}, SHIFT(47),
  [130] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [132] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [134] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [136] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [138] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(29),
  [141] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(29),
  [144] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [146] = {.entry = {.count = 1, .reusable = false}}, SHIFT(29),
  [148] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [150] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [152] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [154] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [156] = {.entry = {.count = 1, .reusable = false}}, SHIFT(30),
  [158] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [160] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [162] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [164] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [166] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [168] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [170] = {.entry = {.count = 1, .reusable = false}}, SHIFT(17),
  [172] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [174] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [176] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(38),
  [179] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [181] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(39),
  [184] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [186] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [188] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [190] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [192] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [194] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
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
