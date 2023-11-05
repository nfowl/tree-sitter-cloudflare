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
#define STATE_COUNT 254
#define LARGE_STATE_COUNT 64
#define SYMBOL_COUNT 207
#define ALIAS_COUNT 0
#define TOKEN_COUNT 166
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
  anon_sym_icmp_DOTtype = 67,
  anon_sym_icmp_DOTcode = 68,
  anon_sym_ip_DOThdr_len = 69,
  anon_sym_ip_DOTlen = 70,
  anon_sym_ip_DOTopt_DOTtype = 71,
  anon_sym_ip_DOTttl = 72,
  anon_sym_tcp_DOTflags = 73,
  anon_sym_tcp_DOTsrcport = 74,
  anon_sym_tcp_DOTdstport = 75,
  anon_sym_udp_DOTdstport = 76,
  anon_sym_udp_DOTsrcport = 77,
  anon_sym_http_DOTrequest_DOTbody_DOTsize = 78,
  anon_sym_http_DOTresponse_DOTcode = 79,
  anon_sym_http_DOTresponse_DOT1xxx_code = 80,
  anon_sym_ip_DOTsrc = 81,
  anon_sym_cf_DOTedge_DOTserver_ip = 82,
  anon_sym_ip_DOTdst = 83,
  anon_sym_http_DOTcookie = 84,
  anon_sym_http_DOThost = 85,
  anon_sym_http_DOTreferer = 86,
  anon_sym_http_DOTrequest_DOTfull_uri = 87,
  anon_sym_http_DOTrequest_DOTmethod = 88,
  anon_sym_http_DOTrequest_DOTuri = 89,
  anon_sym_http_DOTrequest_DOTuri_DOTpath = 90,
  anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension = 91,
  anon_sym_http_DOTrequest_DOTuri_DOTquery = 92,
  anon_sym_http_DOTuser_agent = 93,
  anon_sym_http_DOTrequest_DOTversion = 94,
  anon_sym_http_DOTx_forwarded_for = 95,
  anon_sym_ip_DOTsrc_DOTlat = 96,
  anon_sym_ip_DOTsrc_DOTlon = 97,
  anon_sym_ip_DOTsrc_DOTcity = 98,
  anon_sym_ip_DOTsrc_DOTpostal_code = 99,
  anon_sym_ip_DOTsrc_DOTmetro_code = 100,
  anon_sym_ip_DOTsrc_DOTregion = 101,
  anon_sym_ip_DOTsrc_DOTregion_code = 102,
  anon_sym_ip_DOTsrc_DOTtimezone_DOTname = 103,
  anon_sym_ip_DOTgeoip_DOTcontinent = 104,
  anon_sym_ip_DOTgeoip_DOTcountry = 105,
  anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code = 106,
  anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code = 107,
  anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri = 108,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri = 109,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath = 110,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery = 111,
  anon_sym_cf_DOTbot_management_DOTja3_hash = 112,
  anon_sym_cf_DOTverified_bot_category = 113,
  anon_sym_cf_DOThostname_DOTmetadata = 114,
  anon_sym_cf_DOTworker_DOTupstream_zone = 115,
  anon_sym_cf_DOTcolo_DOTname = 116,
  anon_sym_cf_DOTcolo_DOTregion = 117,
  anon_sym_icmp = 118,
  anon_sym_ip = 119,
  anon_sym_ip_DOTdst_DOTcountry = 120,
  anon_sym_ip_DOTsrc_DOTcountry = 121,
  anon_sym_tcp = 122,
  anon_sym_udp = 123,
  anon_sym_http_DOTrequest_DOTbody_DOTraw = 124,
  anon_sym_http_DOTrequest_DOTbody_DOTmime = 125,
  anon_sym_cf_DOTresponse_DOTerror_type = 126,
  anon_sym_cf_DOTrandom_seed = 127,
  anon_sym_http_DOTrequest_DOTcookies = 128,
  anon_sym_http_DOTrequest_DOTuri_DOTargs = 129,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs = 130,
  anon_sym_http_DOTrequest_DOTheaders = 131,
  anon_sym_http_DOTrequest_DOTbody_DOTform = 132,
  anon_sym_http_DOTresponse_DOTheaders = 133,
  anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames = 134,
  anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues = 135,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames = 136,
  anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues = 137,
  anon_sym_http_DOTrequest_DOTheaders_DOTnames = 138,
  anon_sym_http_DOTrequest_DOTheaders_DOTvalues = 139,
  anon_sym_http_DOTrequest_DOTaccepted_languages = 140,
  anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames = 141,
  anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues = 142,
  anon_sym_http_DOTresponse_DOTheaders_DOTnames = 143,
  anon_sym_http_DOTresponse_DOTheaders_DOTvalues = 144,
  anon_sym_cf_DOTbot_management_DOTdetection_ids = 145,
  anon_sym_ip_DOTgeoip_DOTis_in_european_union = 146,
  anon_sym_ssl = 147,
  anon_sym_cf_DOTbot_management_DOTverified_bot = 148,
  anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed = 149,
  anon_sym_cf_DOTbot_management_DOTcorporate_proxy = 150,
  anon_sym_cf_DOTbot_management_DOTstatic_resource = 151,
  anon_sym_cf_DOTclient_DOTbot = 152,
  anon_sym_cf_DOTtls_client_auth_DOTcert_revoked = 153,
  anon_sym_cf_DOTtls_client_auth_DOTcert_verified = 154,
  anon_sym_sip = 155,
  anon_sym_tcp_DOTflags_DOTack = 156,
  anon_sym_tcp_DOTflags_DOTcwr = 157,
  anon_sym_tcp_DOTflags_DOTecn = 158,
  anon_sym_tcp_DOTflags_DOTfin = 159,
  anon_sym_tcp_DOTflags_DOTpush = 160,
  anon_sym_tcp_DOTflags_DOTreset = 161,
  anon_sym_tcp_DOTflags_DOTsyn = 162,
  anon_sym_tcp_DOTflags_DOTurg = 163,
  anon_sym_http_DOTrequest_DOTheaders_DOTtruncated = 164,
  anon_sym_http_DOTrequest_DOTbody_DOTtruncated = 165,
  sym_source_file = 166,
  sym__expression = 167,
  sym_not_expression = 168,
  sym_in_expression = 169,
  sym_compound_expression = 170,
  sym_ip_set = 171,
  sym_string_set = 172,
  sym_number_set = 173,
  sym_simple_expression = 174,
  sym__bool_lhs = 175,
  sym__number_lhs = 176,
  sym_string_func = 177,
  sym_number_func = 178,
  sym_bool_func = 179,
  sym_array_func = 180,
  sym_group = 181,
  sym_boolean = 182,
  sym__ip = 183,
  sym_ip_range = 184,
  sym_not_operator = 185,
  sym_number_array = 186,
  sym_bool_array = 187,
  sym_string_array = 188,
  sym__string_array_expansion = 189,
  sym_boollike_field = 190,
  sym_numberlike_field = 191,
  sym_stringlike_field = 192,
  sym_number_field = 193,
  sym_ip_field = 194,
  sym_string_field = 195,
  sym_bytes_field = 196,
  sym_map_string_array_field = 197,
  sym_array_string_field = 198,
  sym_array_number_field = 199,
  sym_bool_field = 200,
  aux_sym_source_file_repeat1 = 201,
  aux_sym_ip_set_repeat1 = 202,
  aux_sym_string_set_repeat1 = 203,
  aux_sym_number_set_repeat1 = 204,
  aux_sym_string_func_repeat1 = 205,
  aux_sym_string_func_repeat2 = 206,
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
  [anon_sym_icmp_DOTtype] = "icmp.type",
  [anon_sym_icmp_DOTcode] = "icmp.code",
  [anon_sym_ip_DOThdr_len] = "ip.hdr_len",
  [anon_sym_ip_DOTlen] = "ip.len",
  [anon_sym_ip_DOTopt_DOTtype] = "ip.opt.type",
  [anon_sym_ip_DOTttl] = "ip.ttl",
  [anon_sym_tcp_DOTflags] = "tcp.flags",
  [anon_sym_tcp_DOTsrcport] = "tcp.srcport",
  [anon_sym_tcp_DOTdstport] = "tcp.dstport",
  [anon_sym_udp_DOTdstport] = "udp.dstport",
  [anon_sym_udp_DOTsrcport] = "udp.srcport",
  [anon_sym_http_DOTrequest_DOTbody_DOTsize] = "http.request.body.size",
  [anon_sym_http_DOTresponse_DOTcode] = "http.response.code",
  [anon_sym_http_DOTresponse_DOT1xxx_code] = "http.response.1xxx_code",
  [anon_sym_ip_DOTsrc] = "ip.src",
  [anon_sym_cf_DOTedge_DOTserver_ip] = "cf.edge.server_ip",
  [anon_sym_ip_DOTdst] = "ip.dst",
  [anon_sym_http_DOTcookie] = "http.cookie",
  [anon_sym_http_DOThost] = "http.host",
  [anon_sym_http_DOTreferer] = "http.referer",
  [anon_sym_http_DOTrequest_DOTfull_uri] = "http.request.full_uri",
  [anon_sym_http_DOTrequest_DOTmethod] = "http.request.method",
  [anon_sym_http_DOTrequest_DOTuri] = "http.request.uri",
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = "http.request.uri.path",
  [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = "http.request.uri.path.extension",
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = "http.request.uri.query",
  [anon_sym_http_DOTuser_agent] = "http.user_agent",
  [anon_sym_http_DOTrequest_DOTversion] = "http.request.version",
  [anon_sym_http_DOTx_forwarded_for] = "http.x_forwarded_for",
  [anon_sym_ip_DOTsrc_DOTlat] = "ip.src.lat",
  [anon_sym_ip_DOTsrc_DOTlon] = "ip.src.lon",
  [anon_sym_ip_DOTsrc_DOTcity] = "ip.src.city",
  [anon_sym_ip_DOTsrc_DOTpostal_code] = "ip.src.postal_code",
  [anon_sym_ip_DOTsrc_DOTmetro_code] = "ip.src.metro_code",
  [anon_sym_ip_DOTsrc_DOTregion] = "ip.src.region",
  [anon_sym_ip_DOTsrc_DOTregion_code] = "ip.src.region_code",
  [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = "ip.src.timezone.name",
  [anon_sym_ip_DOTgeoip_DOTcontinent] = "ip.geoip.continent",
  [anon_sym_ip_DOTgeoip_DOTcountry] = "ip.geoip.country",
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = "ip.geoip.subdivision_1_iso_code",
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = "ip.geoip.subdivision_2_iso_code",
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = "raw.http.request.full_uri",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = "raw.http.request.uri",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = "raw.http.request.uri.path",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = "raw.http.request.uri.query",
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = "cf.bot_management.ja3_hash",
  [anon_sym_cf_DOTverified_bot_category] = "cf.verified_bot_category",
  [anon_sym_cf_DOThostname_DOTmetadata] = "cf.hostname.metadata",
  [anon_sym_cf_DOTworker_DOTupstream_zone] = "cf.worker.upstream_zone",
  [anon_sym_cf_DOTcolo_DOTname] = "cf.colo.name",
  [anon_sym_cf_DOTcolo_DOTregion] = "cf.colo.region",
  [anon_sym_icmp] = "icmp",
  [anon_sym_ip] = "ip",
  [anon_sym_ip_DOTdst_DOTcountry] = "ip.dst.country",
  [anon_sym_ip_DOTsrc_DOTcountry] = "ip.src.country",
  [anon_sym_tcp] = "tcp",
  [anon_sym_udp] = "udp",
  [anon_sym_http_DOTrequest_DOTbody_DOTraw] = "http.request.body.raw",
  [anon_sym_http_DOTrequest_DOTbody_DOTmime] = "http.request.body.mime",
  [anon_sym_cf_DOTresponse_DOTerror_type] = "cf.response.error_type",
  [anon_sym_cf_DOTrandom_seed] = "cf.random_seed",
  [anon_sym_http_DOTrequest_DOTcookies] = "http.request.cookies",
  [anon_sym_http_DOTrequest_DOTuri_DOTargs] = "http.request.uri.args",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = "raw.http.request.uri.args",
  [anon_sym_http_DOTrequest_DOTheaders] = "http.request.headers",
  [anon_sym_http_DOTrequest_DOTbody_DOTform] = "http.request.body.form",
  [anon_sym_http_DOTresponse_DOTheaders] = "http.response.headers",
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = "http.request.uri.args.names",
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = "http.request.uri.args.values",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = "raw.http.request.uri.args.names",
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = "raw.http.request.uri.args.values",
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = "http.request.headers.names",
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = "http.request.headers.values",
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = "http.request.accepted_languages",
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = "http.request.body.form.names",
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = "http.request.body.form.values",
  [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = "http.response.headers.names",
  [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = "http.response.headers.values",
  [anon_sym_cf_DOTbot_management_DOTdetection_ids] = "cf.bot_management.detection_ids",
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = "ip.geoip.is_in_european_union",
  [anon_sym_ssl] = "ssl",
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = "cf.bot_management.verified_bot",
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = "cf.bot_management.js_detection.passed",
  [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = "cf.bot_management.corporate_proxy",
  [anon_sym_cf_DOTbot_management_DOTstatic_resource] = "cf.bot_management.static_resource",
  [anon_sym_cf_DOTclient_DOTbot] = "cf.client.bot",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = "cf.tls_client_auth.cert_revoked",
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = "cf.tls_client_auth.cert_verified",
  [anon_sym_sip] = "sip",
  [anon_sym_tcp_DOTflags_DOTack] = "tcp.flags.ack",
  [anon_sym_tcp_DOTflags_DOTcwr] = "tcp.flags.cwr",
  [anon_sym_tcp_DOTflags_DOTecn] = "tcp.flags.ecn",
  [anon_sym_tcp_DOTflags_DOTfin] = "tcp.flags.fin",
  [anon_sym_tcp_DOTflags_DOTpush] = "tcp.flags.push",
  [anon_sym_tcp_DOTflags_DOTreset] = "tcp.flags.reset",
  [anon_sym_tcp_DOTflags_DOTsyn] = "tcp.flags.syn",
  [anon_sym_tcp_DOTflags_DOTurg] = "tcp.flags.urg",
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = "http.request.headers.truncated",
  [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = "http.request.body.truncated",
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
  [sym_string_func] = "string_func",
  [sym_number_func] = "number_func",
  [sym_bool_func] = "bool_func",
  [sym_array_func] = "array_func",
  [sym_group] = "group",
  [sym_boolean] = "boolean",
  [sym__ip] = "_ip",
  [sym_ip_range] = "ip_range",
  [sym_not_operator] = "not_operator",
  [sym_number_array] = "number_array",
  [sym_bool_array] = "bool_array",
  [sym_string_array] = "string_array",
  [sym__string_array_expansion] = "_string_array_expansion",
  [sym_boollike_field] = "boollike_field",
  [sym_numberlike_field] = "numberlike_field",
  [sym_stringlike_field] = "stringlike_field",
  [sym_number_field] = "number_field",
  [sym_ip_field] = "ip_field",
  [sym_string_field] = "string_field",
  [sym_bytes_field] = "bytes_field",
  [sym_map_string_array_field] = "map_string_array_field",
  [sym_array_string_field] = "array_string_field",
  [sym_array_number_field] = "array_number_field",
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
  [anon_sym_icmp_DOTtype] = anon_sym_icmp_DOTtype,
  [anon_sym_icmp_DOTcode] = anon_sym_icmp_DOTcode,
  [anon_sym_ip_DOThdr_len] = anon_sym_ip_DOThdr_len,
  [anon_sym_ip_DOTlen] = anon_sym_ip_DOTlen,
  [anon_sym_ip_DOTopt_DOTtype] = anon_sym_ip_DOTopt_DOTtype,
  [anon_sym_ip_DOTttl] = anon_sym_ip_DOTttl,
  [anon_sym_tcp_DOTflags] = anon_sym_tcp_DOTflags,
  [anon_sym_tcp_DOTsrcport] = anon_sym_tcp_DOTsrcport,
  [anon_sym_tcp_DOTdstport] = anon_sym_tcp_DOTdstport,
  [anon_sym_udp_DOTdstport] = anon_sym_udp_DOTdstport,
  [anon_sym_udp_DOTsrcport] = anon_sym_udp_DOTsrcport,
  [anon_sym_http_DOTrequest_DOTbody_DOTsize] = anon_sym_http_DOTrequest_DOTbody_DOTsize,
  [anon_sym_http_DOTresponse_DOTcode] = anon_sym_http_DOTresponse_DOTcode,
  [anon_sym_http_DOTresponse_DOT1xxx_code] = anon_sym_http_DOTresponse_DOT1xxx_code,
  [anon_sym_ip_DOTsrc] = anon_sym_ip_DOTsrc,
  [anon_sym_cf_DOTedge_DOTserver_ip] = anon_sym_cf_DOTedge_DOTserver_ip,
  [anon_sym_ip_DOTdst] = anon_sym_ip_DOTdst,
  [anon_sym_http_DOTcookie] = anon_sym_http_DOTcookie,
  [anon_sym_http_DOThost] = anon_sym_http_DOThost,
  [anon_sym_http_DOTreferer] = anon_sym_http_DOTreferer,
  [anon_sym_http_DOTrequest_DOTfull_uri] = anon_sym_http_DOTrequest_DOTfull_uri,
  [anon_sym_http_DOTrequest_DOTmethod] = anon_sym_http_DOTrequest_DOTmethod,
  [anon_sym_http_DOTrequest_DOTuri] = anon_sym_http_DOTrequest_DOTuri,
  [anon_sym_http_DOTrequest_DOTuri_DOTpath] = anon_sym_http_DOTrequest_DOTuri_DOTpath,
  [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension,
  [anon_sym_http_DOTrequest_DOTuri_DOTquery] = anon_sym_http_DOTrequest_DOTuri_DOTquery,
  [anon_sym_http_DOTuser_agent] = anon_sym_http_DOTuser_agent,
  [anon_sym_http_DOTrequest_DOTversion] = anon_sym_http_DOTrequest_DOTversion,
  [anon_sym_http_DOTx_forwarded_for] = anon_sym_http_DOTx_forwarded_for,
  [anon_sym_ip_DOTsrc_DOTlat] = anon_sym_ip_DOTsrc_DOTlat,
  [anon_sym_ip_DOTsrc_DOTlon] = anon_sym_ip_DOTsrc_DOTlon,
  [anon_sym_ip_DOTsrc_DOTcity] = anon_sym_ip_DOTsrc_DOTcity,
  [anon_sym_ip_DOTsrc_DOTpostal_code] = anon_sym_ip_DOTsrc_DOTpostal_code,
  [anon_sym_ip_DOTsrc_DOTmetro_code] = anon_sym_ip_DOTsrc_DOTmetro_code,
  [anon_sym_ip_DOTsrc_DOTregion] = anon_sym_ip_DOTsrc_DOTregion,
  [anon_sym_ip_DOTsrc_DOTregion_code] = anon_sym_ip_DOTsrc_DOTregion_code,
  [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = anon_sym_ip_DOTsrc_DOTtimezone_DOTname,
  [anon_sym_ip_DOTgeoip_DOTcontinent] = anon_sym_ip_DOTgeoip_DOTcontinent,
  [anon_sym_ip_DOTgeoip_DOTcountry] = anon_sym_ip_DOTgeoip_DOTcountry,
  [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code,
  [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code,
  [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = anon_sym_raw_DOThttp_DOTrequest_DOTuri,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery,
  [anon_sym_cf_DOTbot_management_DOTja3_hash] = anon_sym_cf_DOTbot_management_DOTja3_hash,
  [anon_sym_cf_DOTverified_bot_category] = anon_sym_cf_DOTverified_bot_category,
  [anon_sym_cf_DOThostname_DOTmetadata] = anon_sym_cf_DOThostname_DOTmetadata,
  [anon_sym_cf_DOTworker_DOTupstream_zone] = anon_sym_cf_DOTworker_DOTupstream_zone,
  [anon_sym_cf_DOTcolo_DOTname] = anon_sym_cf_DOTcolo_DOTname,
  [anon_sym_cf_DOTcolo_DOTregion] = anon_sym_cf_DOTcolo_DOTregion,
  [anon_sym_icmp] = anon_sym_icmp,
  [anon_sym_ip] = anon_sym_ip,
  [anon_sym_ip_DOTdst_DOTcountry] = anon_sym_ip_DOTdst_DOTcountry,
  [anon_sym_ip_DOTsrc_DOTcountry] = anon_sym_ip_DOTsrc_DOTcountry,
  [anon_sym_tcp] = anon_sym_tcp,
  [anon_sym_udp] = anon_sym_udp,
  [anon_sym_http_DOTrequest_DOTbody_DOTraw] = anon_sym_http_DOTrequest_DOTbody_DOTraw,
  [anon_sym_http_DOTrequest_DOTbody_DOTmime] = anon_sym_http_DOTrequest_DOTbody_DOTmime,
  [anon_sym_cf_DOTresponse_DOTerror_type] = anon_sym_cf_DOTresponse_DOTerror_type,
  [anon_sym_cf_DOTrandom_seed] = anon_sym_cf_DOTrandom_seed,
  [anon_sym_http_DOTrequest_DOTcookies] = anon_sym_http_DOTrequest_DOTcookies,
  [anon_sym_http_DOTrequest_DOTuri_DOTargs] = anon_sym_http_DOTrequest_DOTuri_DOTargs,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
  [anon_sym_http_DOTrequest_DOTheaders] = anon_sym_http_DOTrequest_DOTheaders,
  [anon_sym_http_DOTrequest_DOTbody_DOTform] = anon_sym_http_DOTrequest_DOTbody_DOTform,
  [anon_sym_http_DOTresponse_DOTheaders] = anon_sym_http_DOTresponse_DOTheaders,
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
  [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = anon_sym_http_DOTrequest_DOTheaders_DOTnames,
  [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
  [anon_sym_http_DOTrequest_DOTaccepted_languages] = anon_sym_http_DOTrequest_DOTaccepted_languages,
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
  [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = anon_sym_http_DOTresponse_DOTheaders_DOTnames,
  [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [anon_sym_cf_DOTbot_management_DOTdetection_ids] = anon_sym_cf_DOTbot_management_DOTdetection_ids,
  [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = anon_sym_ip_DOTgeoip_DOTis_in_european_union,
  [anon_sym_ssl] = anon_sym_ssl,
  [anon_sym_cf_DOTbot_management_DOTverified_bot] = anon_sym_cf_DOTbot_management_DOTverified_bot,
  [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
  [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = anon_sym_cf_DOTbot_management_DOTcorporate_proxy,
  [anon_sym_cf_DOTbot_management_DOTstatic_resource] = anon_sym_cf_DOTbot_management_DOTstatic_resource,
  [anon_sym_cf_DOTclient_DOTbot] = anon_sym_cf_DOTclient_DOTbot,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
  [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
  [anon_sym_sip] = anon_sym_sip,
  [anon_sym_tcp_DOTflags_DOTack] = anon_sym_tcp_DOTflags_DOTack,
  [anon_sym_tcp_DOTflags_DOTcwr] = anon_sym_tcp_DOTflags_DOTcwr,
  [anon_sym_tcp_DOTflags_DOTecn] = anon_sym_tcp_DOTflags_DOTecn,
  [anon_sym_tcp_DOTflags_DOTfin] = anon_sym_tcp_DOTflags_DOTfin,
  [anon_sym_tcp_DOTflags_DOTpush] = anon_sym_tcp_DOTflags_DOTpush,
  [anon_sym_tcp_DOTflags_DOTreset] = anon_sym_tcp_DOTflags_DOTreset,
  [anon_sym_tcp_DOTflags_DOTsyn] = anon_sym_tcp_DOTflags_DOTsyn,
  [anon_sym_tcp_DOTflags_DOTurg] = anon_sym_tcp_DOTflags_DOTurg,
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
  [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = anon_sym_http_DOTrequest_DOTbody_DOTtruncated,
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
  [sym_string_func] = sym_string_func,
  [sym_number_func] = sym_number_func,
  [sym_bool_func] = sym_bool_func,
  [sym_array_func] = sym_array_func,
  [sym_group] = sym_group,
  [sym_boolean] = sym_boolean,
  [sym__ip] = sym__ip,
  [sym_ip_range] = sym_ip_range,
  [sym_not_operator] = sym_not_operator,
  [sym_number_array] = sym_number_array,
  [sym_bool_array] = sym_bool_array,
  [sym_string_array] = sym_string_array,
  [sym__string_array_expansion] = sym__string_array_expansion,
  [sym_boollike_field] = sym_boollike_field,
  [sym_numberlike_field] = sym_numberlike_field,
  [sym_stringlike_field] = sym_stringlike_field,
  [sym_number_field] = sym_number_field,
  [sym_ip_field] = sym_ip_field,
  [sym_string_field] = sym_string_field,
  [sym_bytes_field] = sym_bytes_field,
  [sym_map_string_array_field] = sym_map_string_array_field,
  [sym_array_string_field] = sym_array_string_field,
  [sym_array_number_field] = sym_array_number_field,
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
  [anon_sym_icmp_DOTtype] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_icmp_DOTcode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOThdr_len] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTlen] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTopt_DOTtype] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTttl] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTsrcport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTdstport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp_DOTdstport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp_DOTsrcport] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTsize] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTcode] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOT1xxx_code] = {
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
  [anon_sym_ip_DOTdst] = {
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
  [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = {
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
  [anon_sym_ip_DOTsrc_DOTregion] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTregion_code] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = {
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
  [anon_sym_cf_DOTverified_bot_category] = {
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
  [anon_sym_cf_DOTcolo_DOTname] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTcolo_DOTregion] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_icmp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTdst_DOTcountry] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip_DOTsrc_DOTcountry] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTraw] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTmime] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTresponse_DOTerror_type] = {
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
  [anon_sym_http_DOTrequest_DOTuri_DOTargs] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTform] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTheaders] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = {
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
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTdetection_ids] = {
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
  [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_cf_DOTbot_management_DOTstatic_resource] = {
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
  [anon_sym_sip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTack] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTcwr] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTecn] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTfin] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTpush] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTreset] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTsyn] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp_DOTflags_DOTurg] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = {
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
  [sym_array_func] = {
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
  [sym_number_array] = {
    .visible = true,
    .named = true,
  },
  [sym_bool_array] = {
    .visible = true,
    .named = true,
  },
  [sym_string_array] = {
    .visible = true,
    .named = true,
  },
  [sym__string_array_expansion] = {
    .visible = false,
    .named = true,
  },
  [sym_boollike_field] = {
    .visible = true,
    .named = true,
  },
  [sym_numberlike_field] = {
    .visible = true,
    .named = true,
  },
  [sym_stringlike_field] = {
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
  [sym_map_string_array_field] = {
    .visible = true,
    .named = true,
  },
  [sym_array_string_field] = {
    .visible = true,
    .named = true,
  },
  [sym_array_number_field] = {
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
  [1] = {.index = 0, .length = 1},
  [2] = {.index = 1, .length = 3},
  [3] = {.index = 4, .length = 3},
  [4] = {.index = 7, .length = 2},
  [5] = {.index = 9, .length = 3},
  [6] = {.index = 12, .length = 2},
  [7] = {.index = 14, .length = 1},
  [8] = {.index = 15, .length = 1},
  [9] = {.index = 16, .length = 4},
  [10] = {.index = 20, .length = 3},
  [11] = {.index = 23, .length = 3},
  [12] = {.index = 26, .length = 1},
  [13] = {.index = 27, .length = 2},
  [14] = {.index = 29, .length = 2},
  [15] = {.index = 31, .length = 4},
  [16] = {.index = 35, .length = 3},
  [17] = {.index = 38, .length = 4},
  [18] = {.index = 42, .length = 3},
  [19] = {.index = 45, .length = 5},
  [20] = {.index = 50, .length = 5},
  [21] = {.index = 55, .length = 4},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_inner, 1},
  [1] =
    {field_lhs, 0},
    {field_operator, 1},
    {field_rhs, 2},
  [4] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
  [7] =
    {field_field, 2},
    {field_func, 0},
  [9] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_seed, 2},
  [12] =
    {field_func, 0},
    {field_seed, 2},
  [14] =
    {field_index, 2},
  [15] =
    {field_key, 2},
  [16] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_keys, 3},
  [20] =
    {field_field, 2},
    {field_func, 0},
    {field_keys, 3},
  [23] =
    {field_field, 2},
    {field_field, 3},
    {field_func, 0},
  [26] =
    {field_func, 0},
  [27] =
    {field_ip, 0},
    {field_mask, 2},
  [29] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
  [31] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_replacement, 4},
  [35] =
    {field_field, 2},
    {field_func, 0},
    {field_replacement, 4},
  [38] =
    {field_field, 2},
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_value, 4},
  [42] =
    {field_field, 2},
    {field_func, 0},
    {field_value, 4},
  [45] =
    {field_func, 0},
    {field_lhs, 2},
    {field_lhs, 3},
    {field_operator, 4},
    {field_rhs, 5},
  [50] =
    {field_func, 0},
    {field_key, 2, .inherited = true},
    {field_regex, 4},
    {field_replacement, 6},
    {field_source, 2},
  [55] =
    {field_func, 0},
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
  [44] = 43,
  [45] = 42,
  [46] = 46,
  [47] = 47,
  [48] = 48,
  [49] = 49,
  [50] = 47,
  [51] = 48,
  [52] = 52,
  [53] = 53,
  [54] = 52,
  [55] = 55,
  [56] = 56,
  [57] = 55,
  [58] = 58,
  [59] = 58,
  [60] = 56,
  [61] = 53,
  [62] = 62,
  [63] = 63,
  [64] = 64,
  [65] = 64,
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
  [94] = 89,
  [95] = 95,
  [96] = 96,
  [97] = 97,
  [98] = 98,
  [99] = 99,
  [100] = 100,
  [101] = 101,
  [102] = 102,
  [103] = 103,
  [104] = 102,
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
  [132] = 131,
  [133] = 111,
  [134] = 134,
  [135] = 135,
  [136] = 136,
  [137] = 113,
  [138] = 116,
  [139] = 139,
  [140] = 140,
  [141] = 141,
  [142] = 142,
  [143] = 143,
  [144] = 144,
  [145] = 118,
  [146] = 146,
  [147] = 147,
  [148] = 148,
  [149] = 149,
  [150] = 150,
  [151] = 109,
  [152] = 152,
  [153] = 153,
  [154] = 154,
  [155] = 155,
  [156] = 156,
  [157] = 112,
  [158] = 158,
  [159] = 159,
  [160] = 160,
  [161] = 161,
  [162] = 162,
  [163] = 163,
  [164] = 164,
  [165] = 114,
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
  [184] = 120,
  [185] = 185,
  [186] = 186,
  [187] = 187,
  [188] = 124,
  [189] = 189,
  [190] = 125,
  [191] = 191,
  [192] = 192,
  [193] = 193,
  [194] = 194,
  [195] = 195,
  [196] = 196,
  [197] = 126,
  [198] = 198,
  [199] = 199,
  [200] = 200,
  [201] = 201,
  [202] = 202,
  [203] = 203,
  [204] = 204,
  [205] = 205,
  [206] = 206,
  [207] = 207,
  [208] = 121,
  [209] = 122,
  [210] = 210,
  [211] = 211,
  [212] = 212,
  [213] = 198,
  [214] = 181,
  [215] = 179,
  [216] = 146,
  [217] = 217,
  [218] = 134,
  [219] = 219,
  [220] = 162,
  [221] = 166,
  [222] = 194,
  [223] = 123,
  [224] = 130,
  [225] = 202,
  [226] = 226,
  [227] = 227,
  [228] = 228,
  [229] = 229,
  [230] = 141,
  [231] = 135,
  [232] = 186,
  [233] = 233,
  [234] = 234,
  [235] = 210,
  [236] = 234,
  [237] = 237,
  [238] = 200,
  [239] = 189,
  [240] = 177,
  [241] = 160,
  [242] = 242,
  [243] = 237,
  [244] = 244,
  [245] = 245,
  [246] = 233,
  [247] = 144,
  [248] = 139,
  [249] = 244,
  [250] = 228,
  [251] = 193,
  [252] = 242,
  [253] = 245,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(1027);
      if (lookahead == '!') ADVANCE(1093);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(1037);
      if (lookahead == '$') ADVANCE(1088);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(1055);
      if (lookahead == ')') ADVANCE(1057);
      if (lookahead == '*') ADVANCE(1097);
      if (lookahead == ',') ADVANCE(1056);
      if (lookahead == '/') ADVANCE(1082);
      if (lookahead == '3') ADVANCE(1072);
      if (lookahead == '<') ADVANCE(1047);
      if (lookahead == '=') ADVANCE(60);
      if (lookahead == '>') ADVANCE(1049);
      if (lookahead == '[') ADVANCE(1095);
      if (lookahead == ']') ADVANCE(1096);
      if (lookahead == '^') ADVANCE(62);
      if (lookahead == 'a') ADVANCE(511);
      if (lookahead == 'c') ADVANCE(411);
      if (lookahead == 'e') ADVANCE(562);
      if (lookahead == 'f') ADVANCE(113);
      if (lookahead == 'g') ADVANCE(272);
      if (lookahead == 'h') ADVANCE(897);
      if (lookahead == 'i') ADVANCE(181);
      if (lookahead == 'l') ADVANCE(273);
      if (lookahead == 'm') ADVANCE(116);
      if (lookahead == 'n') ADVANCE(275);
      if (lookahead == 'o') ADVANCE(740);
      if (lookahead == 'r') ADVANCE(108);
      if (lookahead == 's') ADVANCE(454);
      if (lookahead == 't') ADVANCE(189);
      if (lookahead == 'u') ADVANCE(240);
      if (lookahead == 'x') ADVANCE(628);
      if (lookahead == '{') ADVANCE(1035);
      if (lookahead == '|') ADVANCE(1025);
      if (lookahead == '}') ADVANCE(1036);
      if (lookahead == '~') ADVANCE(1053);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(1073);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(1073);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(59);
      if (lookahead == '"') ADVANCE(2);
      if (lookahead == '#') ADVANCE(1037);
      if (lookahead == ')') ADVANCE(1057);
      if (lookahead == ',') ADVANCE(1056);
      if (lookahead == '<') ADVANCE(1047);
      if (lookahead == '=') ADVANCE(60);
      if (lookahead == '>') ADVANCE(1049);
      if (lookahead == 'c') ADVANCE(413);
      if (lookahead == 'e') ADVANCE(737);
      if (lookahead == 'g') ADVANCE(272);
      if (lookahead == 'h') ADVANCE(955);
      if (lookahead == 'i') ADVANCE(208);
      if (lookahead == 'l') ADVANCE(306);
      if (lookahead == 'm') ADVANCE(116);
      if (lookahead == 'n') ADVANCE(274);
      if (lookahead == 'r') ADVANCE(108);
      if (lookahead == 't') ADVANCE(199);
      if (lookahead == 'u') ADVANCE(249);
      if (lookahead == '}') ADVANCE(1036);
      if (lookahead == '~') ADVANCE(1053);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1073);
      END_STATE();
    case 2:
      if (lookahead == '"') ADVANCE(1074);
      if (lookahead != 0) ADVANCE(2);
      END_STATE();
    case 3:
      if (lookahead == '#') ADVANCE(1037);
      if (lookahead == '3') ADVANCE(1084);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(1085);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (('4' <= lookahead && lookahead <= '9')) ADVANCE(1083);
      END_STATE();
    case 4:
      if (lookahead == '&') ADVANCE(1029);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(173);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(191);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(186);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(604);
      END_STATE();
    case 9:
      if (lookahead == '.') ADVANCE(131);
      END_STATE();
    case 10:
      if (lookahead == '.') ADVANCE(148);
      END_STATE();
    case 11:
      if (lookahead == '.') ADVANCE(52);
      END_STATE();
    case 12:
      if (lookahead == '.') ADVANCE(423);
      END_STATE();
    case 13:
      if (lookahead == '.') ADVANCE(215);
      END_STATE();
    case 14:
      if (lookahead == '.') ADVANCE(422);
      END_STATE();
    case 15:
      if (lookahead == '.') ADVANCE(557);
      END_STATE();
    case 16:
      if (lookahead == '.') ADVANCE(56);
      END_STATE();
    case 17:
      if (lookahead == '.') ADVANCE(56);
      if (lookahead == '5') ADVANCE(18);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(16);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(20);
      END_STATE();
    case 18:
      if (lookahead == '.') ADVANCE(56);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(16);
      END_STATE();
    case 19:
      if (lookahead == '.') ADVANCE(56);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(20);
      END_STATE();
    case 20:
      if (lookahead == '.') ADVANCE(56);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(16);
      END_STATE();
    case 21:
      if (lookahead == '.') ADVANCE(180);
      END_STATE();
    case 22:
      if (lookahead == '.') ADVANCE(197);
      END_STATE();
    case 23:
      if (lookahead == '.') ADVANCE(149);
      END_STATE();
    case 24:
      if (lookahead == '.') ADVANCE(421);
      END_STATE();
    case 25:
      if (lookahead == '.') ADVANCE(174);
      END_STATE();
    case 26:
      if (lookahead == '.') ADVANCE(452);
      END_STATE();
    case 27:
      if (lookahead == '.') ADVANCE(504);
      END_STATE();
    case 28:
      if (lookahead == '.') ADVANCE(177);
      END_STATE();
    case 29:
      if (lookahead == '.') ADVANCE(54);
      END_STATE();
    case 30:
      if (lookahead == '.') ADVANCE(54);
      if (lookahead == '5') ADVANCE(31);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(29);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(33);
      END_STATE();
    case 31:
      if (lookahead == '.') ADVANCE(54);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(29);
      END_STATE();
    case 32:
      if (lookahead == '.') ADVANCE(54);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(33);
      END_STATE();
    case 33:
      if (lookahead == '.') ADVANCE(54);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(29);
      END_STATE();
    case 34:
      if (lookahead == '.') ADVANCE(842);
      END_STATE();
    case 35:
      if (lookahead == '.') ADVANCE(217);
      END_STATE();
    case 36:
      if (lookahead == '.') ADVANCE(946);
      END_STATE();
    case 37:
      if (lookahead == '.') ADVANCE(726);
      END_STATE();
    case 38:
      if (lookahead == '.') ADVANCE(453);
      END_STATE();
    case 39:
      if (lookahead == '.') ADVANCE(55);
      END_STATE();
    case 40:
      if (lookahead == '.') ADVANCE(55);
      if (lookahead == '5') ADVANCE(41);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(39);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(43);
      END_STATE();
    case 41:
      if (lookahead == '.') ADVANCE(55);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(39);
      END_STATE();
    case 42:
      if (lookahead == '.') ADVANCE(55);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(43);
      END_STATE();
    case 43:
      if (lookahead == '.') ADVANCE(55);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(39);
      END_STATE();
    case 44:
      if (lookahead == '.') ADVANCE(964);
      END_STATE();
    case 45:
      if (lookahead == '.') ADVANCE(196);
      END_STATE();
    case 46:
      if (lookahead == '.') ADVANCE(612);
      END_STATE();
    case 47:
      if (lookahead == '.') ADVANCE(555);
      END_STATE();
    case 48:
      if (lookahead == '.') ADVANCE(787);
      END_STATE();
    case 49:
      if (lookahead == '.') ADVANCE(354);
      END_STATE();
    case 50:
      if (lookahead == '.') ADVANCE(870);
      END_STATE();
    case 51:
      if (lookahead == '.') ADVANCE(192);
      END_STATE();
    case 52:
      if (lookahead == '1') ADVANCE(999);
      if (lookahead == 'c') ADVANCE(685);
      if (lookahead == 'h') ADVANCE(403);
      END_STATE();
    case 53:
      if (lookahead == '1') ADVANCE(84);
      if (lookahead == '2') ADVANCE(107);
      END_STATE();
    case 54:
      if (lookahead == '2') ADVANCE(1078);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(1081);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(1080);
      END_STATE();
    case 55:
      if (lookahead == '2') ADVANCE(30);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(32);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(33);
      END_STATE();
    case 56:
      if (lookahead == '2') ADVANCE(40);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(42);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(43);
      END_STATE();
    case 57:
      if (lookahead == '3') ADVANCE(75);
      END_STATE();
    case 58:
      if (lookahead == '4') ADVANCE(1065);
      END_STATE();
    case 59:
      if (lookahead == '=') ADVANCE(1046);
      END_STATE();
    case 60:
      if (lookahead == '=') ADVANCE(1045);
      END_STATE();
    case 61:
      if (lookahead == ']') ADVANCE(1071);
      END_STATE();
    case 62:
      if (lookahead == '^') ADVANCE(1032);
      END_STATE();
    case 63:
      if (lookahead == '_') ADVANCE(503);
      END_STATE();
    case 64:
      if (lookahead == '_') ADVANCE(175);
      END_STATE();
    case 65:
      if (lookahead == '_') ADVANCE(471);
      END_STATE();
    case 66:
      if (lookahead == '_') ADVANCE(53);
      END_STATE();
    case 67:
      if (lookahead == '_') ADVANCE(795);
      END_STATE();
    case 68:
      if (lookahead == '_') ADVANCE(538);
      END_STATE();
    case 69:
      if (lookahead == '_') ADVANCE(993);
      END_STATE();
    case 70:
      if (lookahead == '_') ADVANCE(843);
      END_STATE();
    case 71:
      if (lookahead == '_') ADVANCE(414);
      END_STATE();
    case 72:
      if (lookahead == '_') ADVANCE(242);
      END_STATE();
    case 73:
      if (lookahead == '_') ADVANCE(195);
      END_STATE();
    case 74:
      if (lookahead == '_') ADVANCE(523);
      END_STATE();
    case 75:
      if (lookahead == '_') ADVANCE(449);
      END_STATE();
    case 76:
      if (lookahead == '_') ADVANCE(124);
      END_STATE();
    case 77:
      if (lookahead == '_') ADVANCE(210);
      END_STATE();
    case 78:
      if (lookahead == '_') ADVANCE(526);
      END_STATE();
    case 79:
      if (lookahead == '_') ADVANCE(716);
      END_STATE();
    case 80:
      if (lookahead == '_') ADVANCE(482);
      END_STATE();
    case 81:
      if (lookahead == '_') ADVANCE(323);
      END_STATE();
    case 82:
      if (lookahead == '_') ADVANCE(770);
      END_STATE();
    case 83:
      if (lookahead == '_') ADVANCE(969);
      END_STATE();
    case 84:
      if (lookahead == '_') ADVANCE(476);
      END_STATE();
    case 85:
      if (lookahead == '_') ADVANCE(721);
      END_STATE();
    case 86:
      if (lookahead == '_') ADVANCE(856);
      END_STATE();
    case 87:
      if (lookahead == '_') ADVANCE(967);
      END_STATE();
    case 88:
      if (lookahead == '_') ADVANCE(971);
      END_STATE();
    case 89:
      if (lookahead == '_') ADVANCE(484);
      END_STATE();
    case 90:
      if (lookahead == '_') ADVANCE(271);
      END_STATE();
    case 91:
      if (lookahead == '_') ADVANCE(796);
      END_STATE();
    case 92:
      if (lookahead == '_') ADVANCE(996);
      END_STATE();
    case 93:
      if (lookahead == '_') ADVANCE(178);
      END_STATE();
    case 94:
      if (lookahead == '_') ADVANCE(1024);
      END_STATE();
    case 95:
      if (lookahead == '_') ADVANCE(420);
      END_STATE();
    case 96:
      if (lookahead == '_') ADVANCE(151);
      END_STATE();
    case 97:
      if (lookahead == '_') ADVANCE(873);
      END_STATE();
    case 98:
      if (lookahead == '_') ADVANCE(179);
      END_STATE();
    case 99:
      if (lookahead == '_') ADVANCE(221);
      END_STATE();
    case 100:
      if (lookahead == '_') ADVANCE(948);
      END_STATE();
    case 101:
      if (lookahead == '_') ADVANCE(223);
      END_STATE();
    case 102:
      if (lookahead == '_') ADVANCE(225);
      END_STATE();
    case 103:
      if (lookahead == '_') ADVANCE(226);
      END_STATE();
    case 104:
      if (lookahead == '_') ADVANCE(227);
      END_STATE();
    case 105:
      if (lookahead == '_') ADVANCE(878);
      END_STATE();
    case 106:
      if (lookahead == '_') ADVANCE(560);
      END_STATE();
    case 107:
      if (lookahead == '_') ADVANCE(502);
      END_STATE();
    case 108:
      if (lookahead == 'a') ADVANCE(992);
      if (lookahead == 'e') ADVANCE(428);
      END_STATE();
    case 109:
      if (lookahead == 'a') ADVANCE(412);
      if (lookahead == 'o') ADVANCE(748);
      END_STATE();
    case 110:
      if (lookahead == 'a') ADVANCE(57);
      END_STATE();
    case 111:
      if (lookahead == 'a') ADVANCE(57);
      if (lookahead == 's') ADVANCE(90);
      END_STATE();
    case 112:
      if (lookahead == 'a') ADVANCE(1155);
      END_STATE();
    case 113:
      if (lookahead == 'a') ADVANCE(517);
      END_STATE();
    case 114:
      if (lookahead == 'a') ADVANCE(579);
      if (lookahead == 'b') ADVANCE(644);
      if (lookahead == 'm') ADVANCE(123);
      if (lookahead == 'o') ADVANCE(713);
      if (lookahead == 'v') ADVANCE(709);
      END_STATE();
    case 115:
      if (lookahead == 'a') ADVANCE(431);
      END_STATE();
    case 116:
      if (lookahead == 'a') ADVANCE(881);
      END_STATE();
    case 117:
      if (lookahead == 'a') ADVANCE(754);
      END_STATE();
    case 118:
      if (lookahead == 'a') ADVANCE(580);
      if (lookahead == 'e') ADVANCE(845);
      END_STATE();
    case 119:
      if (lookahead == 'a') ADVANCE(465);
      END_STATE();
    case 120:
      if (lookahead == 'a') ADVANCE(544);
      END_STATE();
    case 121:
      if (lookahead == 'a') ADVANCE(991);
      END_STATE();
    case 122:
      if (lookahead == 'a') ADVANCE(542);
      END_STATE();
    case 123:
      if (lookahead == 'a') ADVANCE(518);
      END_STATE();
    case 124:
      if (lookahead == 'a') ADVANCE(970);
      END_STATE();
    case 125:
      if (lookahead == 'a') ADVANCE(883);
      END_STATE();
    case 126:
      if (lookahead == 'a') ADVANCE(201);
      END_STATE();
    case 127:
      if (lookahead == 'a') ADVANCE(190);
      if (lookahead == 'c') ADVANCE(994);
      if (lookahead == 'e') ADVANCE(198);
      if (lookahead == 'f') ADVANCE(473);
      if (lookahead == 'p') ADVANCE(962);
      if (lookahead == 'r') ADVANCE(390);
      if (lookahead == 's') ADVANCE(1016);
      if (lookahead == 'u') ADVANCE(753);
      END_STATE();
    case 128:
      if (lookahead == 'a') ADVANCE(263);
      END_STATE();
    case 129:
      if (lookahead == 'a') ADVANCE(535);
      END_STATE();
    case 130:
      if (lookahead == 'a') ADVANCE(265);
      END_STATE();
    case 131:
      if (lookahead == 'a') ADVANCE(851);
      if (lookahead == 'c') ADVANCE(627);
      if (lookahead == 'i') ADVANCE(848);
      if (lookahead == 's') ADVANCE(958);
      END_STATE();
    case 132:
      if (lookahead == 'a') ADVANCE(584);
      END_STATE();
    case 133:
      if (lookahead == 'a') ADVANCE(527);
      END_STATE();
    case 134:
      if (lookahead == 'a') ADVANCE(942);
      END_STATE();
    case 135:
      if (lookahead == 'a') ADVANCE(886);
      if (lookahead == 'o') ADVANCE(568);
      END_STATE();
    case 136:
      if (lookahead == 'a') ADVANCE(802);
      END_STATE();
    case 137:
      if (lookahead == 'a') ADVANCE(846);
      END_STATE();
    case 138:
      if (lookahead == 'a') ADVANCE(585);
      END_STATE();
    case 139:
      if (lookahead == 'a') ADVANCE(797);
      if (lookahead == 'p') ADVANCE(142);
      if (lookahead == 'q') ADVANCE(978);
      END_STATE();
    case 140:
      if (lookahead == 'a') ADVANCE(871);
      END_STATE();
    case 141:
      if (lookahead == 'a') ADVANCE(915);
      END_STATE();
    case 142:
      if (lookahead == 'a') ADVANCE(909);
      END_STATE();
    case 143:
      if (lookahead == 'a') ADVANCE(923);
      END_STATE();
    case 144:
      if (lookahead == 'a') ADVANCE(911);
      END_STATE();
    case 145:
      if (lookahead == 'a') ADVANCE(940);
      END_STATE();
    case 146:
      if (lookahead == 'a') ADVANCE(541);
      END_STATE();
    case 147:
      if (lookahead == 'a') ADVANCE(435);
      END_STATE();
    case 148:
      if (lookahead == 'a') ADVANCE(209);
      if (lookahead == 'b') ADVANCE(642);
      if (lookahead == 'c') ADVANCE(694);
      if (lookahead == 'f') ADVANCE(961);
      if (lookahead == 'h') ADVANCE(384);
      if (lookahead == 'm') ADVANCE(369);
      if (lookahead == 't') ADVANCE(490);
      if (lookahead == 'u') ADVANCE(762);
      if (lookahead == 'v') ADVANCE(360);
      END_STATE();
    case 149:
      if (lookahead == 'a') ADVANCE(209);
      if (lookahead == 'b') ADVANCE(669);
      if (lookahead == 'c') ADVANCE(694);
      if (lookahead == 'f') ADVANCE(961);
      if (lookahead == 'h') ADVANCE(404);
      if (lookahead == 'm') ADVANCE(369);
      if (lookahead == 'u') ADVANCE(762);
      if (lookahead == 'v') ADVANCE(360);
      END_STATE();
    case 150:
      if (lookahead == 'a') ADVANCE(934);
      END_STATE();
    case 151:
      if (lookahead == 'a') ADVANCE(437);
      END_STATE();
    case 152:
      if (lookahead == 'a') ADVANCE(546);
      END_STATE();
    case 153:
      if (lookahead == 'a') ADVANCE(782);
      END_STATE();
    case 154:
      if (lookahead == 'a') ADVANCE(436);
      END_STATE();
    case 155:
      if (lookahead == 'a') ADVANCE(593);
      END_STATE();
    case 156:
      if (lookahead == 'a') ADVANCE(936);
      END_STATE();
    case 157:
      if (lookahead == 'a') ADVANCE(547);
      END_STATE();
    case 158:
      if (lookahead == 'a') ADVANCE(938);
      END_STATE();
    case 159:
      if (lookahead == 'a') ADVANCE(549);
      END_STATE();
    case 160:
      if (lookahead == 'a') ADVANCE(550);
      END_STATE();
    case 161:
      if (lookahead == 'a') ADVANCE(551);
      END_STATE();
    case 162:
      if (lookahead == 'a') ADVANCE(552);
      END_STATE();
    case 163:
      if (lookahead == 'a') ADVANCE(553);
      END_STATE();
    case 164:
      if (lookahead == 'a') ADVANCE(266);
      END_STATE();
    case 165:
      if (lookahead == 'a') ADVANCE(528);
      END_STATE();
    case 166:
      if (lookahead == 'a') ADVANCE(801);
      if (lookahead == 'p') ADVANCE(144);
      if (lookahead == 'q') ADVANCE(979);
      END_STATE();
    case 167:
      if (lookahead == 'a') ADVANCE(440);
      END_STATE();
    case 168:
      if (lookahead == 'a') ADVANCE(267);
      END_STATE();
    case 169:
      if (lookahead == 'a') ADVANCE(529);
      END_STATE();
    case 170:
      if (lookahead == 'a') ADVANCE(530);
      END_STATE();
    case 171:
      if (lookahead == 'a') ADVANCE(531);
      END_STATE();
    case 172:
      if (lookahead == 'a') ADVANCE(622);
      END_STATE();
    case 173:
      if (lookahead == 'b') ADVANCE(640);
      if (lookahead == 'c') ADVANCE(516);
      if (lookahead == 'e') ADVANCE(231);
      if (lookahead == 'h') ADVANCE(671);
      if (lookahead == 'r') ADVANCE(118);
      if (lookahead == 't') ADVANCE(447);
      if (lookahead == 'v') ADVANCE(320);
      if (lookahead == 'w') ADVANCE(109);
      END_STATE();
    case 174:
      if (lookahead == 'b') ADVANCE(640);
      if (lookahead == 'c') ADVANCE(516);
      if (lookahead == 'e') ADVANCE(231);
      if (lookahead == 'h') ADVANCE(671);
      if (lookahead == 'r') ADVANCE(309);
      if (lookahead == 't') ADVANCE(447);
      if (lookahead == 'v') ADVANCE(320);
      if (lookahead == 'w') ADVANCE(109);
      END_STATE();
    case 175:
      if (lookahead == 'b') ADVANCE(1015);
      END_STATE();
    case 176:
      if (lookahead == 'b') ADVANCE(246);
      END_STATE();
    case 177:
      if (lookahead == 'b') ADVANCE(653);
      END_STATE();
    case 178:
      if (lookahead == 'b') ADVANCE(658);
      END_STATE();
    case 179:
      if (lookahead == 'b') ADVANCE(664);
      END_STATE();
    case 180:
      if (lookahead == 'b') ADVANCE(699);
      if (lookahead == 'c') ADVANCE(634);
      if (lookahead == 'h') ADVANCE(671);
      if (lookahead == 'r') ADVANCE(309);
      if (lookahead == 'v') ADVANCE(320);
      if (lookahead == 'w') ADVANCE(641);
      END_STATE();
    case 181:
      if (lookahead == 'c') ADVANCE(539);
      if (lookahead == 'n') ADVANCE(1028);
      if (lookahead == 'p') ADVANCE(1161);
      END_STATE();
    case 182:
      if (lookahead == 'c') ADVANCE(539);
      if (lookahead == 'p') ADVANCE(1161);
      END_STATE();
    case 183:
      if (lookahead == 'c') ADVANCE(448);
      END_STATE();
    case 184:
      if (lookahead == 'c') ADVANCE(1122);
      END_STATE();
    case 185:
      if (lookahead == 'c') ADVANCE(1086);
      END_STATE();
    case 186:
      if (lookahead == 'c') ADVANCE(472);
      if (lookahead == 'l') ADVANCE(135);
      if (lookahead == 'm') ADVANCE(380);
      if (lookahead == 'p') ADVANCE(680);
      if (lookahead == 'r') ADVANCE(311);
      if (lookahead == 't') ADVANCE(483);
      END_STATE();
    case 187:
      if (lookahead == 'c') ADVANCE(1098);
      END_STATE();
    case 188:
      if (lookahead == 'c') ADVANCE(1099);
      END_STATE();
    case 189:
      if (lookahead == 'c') ADVANCE(701);
      if (lookahead == 'o') ADVANCE(70);
      if (lookahead == 'r') ADVANCE(957);
      END_STATE();
    case 190:
      if (lookahead == 'c') ADVANCE(505);
      END_STATE();
    case 191:
      if (lookahead == 'c') ADVANCE(643);
      if (lookahead == 'h') ADVANCE(675);
      if (lookahead == 'r') ADVANCE(280);
      if (lookahead == 'u') ADVANCE(868);
      if (lookahead == 'x') ADVANCE(71);
      END_STATE();
    case 192:
      if (lookahead == 'c') ADVANCE(643);
      if (lookahead == 'h') ADVANCE(675);
      if (lookahead == 'r') ADVANCE(405);
      if (lookahead == 'u') ADVANCE(868);
      if (lookahead == 'x') ADVANCE(71);
      END_STATE();
    case 193:
      if (lookahead == 'c') ADVANCE(185);
      END_STATE();
    case 194:
      if (lookahead == 'c') ADVANCE(666);
      if (lookahead == 't') ADVANCE(1018);
      END_STATE();
    case 195:
      if (lookahead == 'c') ADVANCE(532);
      END_STATE();
    case 196:
      if (lookahead == 'c') ADVANCE(631);
      END_STATE();
    case 197:
      if (lookahead == 'c') ADVANCE(627);
      if (lookahead == 's') ADVANCE(958);
      END_STATE();
    case 198:
      if (lookahead == 'c') ADVANCE(570);
      END_STATE();
    case 199:
      if (lookahead == 'c') ADVANCE(705);
      if (lookahead == 'o') ADVANCE(70);
      END_STATE();
    case 200:
      if (lookahead == 'c') ADVANCE(7);
      END_STATE();
    case 201:
      if (lookahead == 'c') ADVANCE(289);
      END_STATE();
    case 202:
      if (lookahead == 'c') ADVANCE(291);
      END_STATE();
    case 203:
      if (lookahead == 'c') ADVANCE(950);
      END_STATE();
    case 204:
      if (lookahead == 'c') ADVANCE(382);
      END_STATE();
    case 205:
      if (lookahead == 'c') ADVANCE(305);
      END_STATE();
    case 206:
      if (lookahead == 'c') ADVANCE(125);
      END_STATE();
    case 207:
      if (lookahead == 'c') ADVANCE(125);
      if (lookahead == 't') ADVANCE(119);
      END_STATE();
    case 208:
      if (lookahead == 'c') ADVANCE(543);
      if (lookahead == 'n') ADVANCE(1028);
      if (lookahead == 'p') ADVANCE(1162);
      END_STATE();
    case 209:
      if (lookahead == 'c') ADVANCE(204);
      END_STATE();
    case 210:
      if (lookahead == 'c') ADVANCE(150);
      END_STATE();
    case 211:
      if (lookahead == 'c') ADVANCE(682);
      END_STATE();
    case 212:
      if (lookahead == 'c') ADVANCE(686);
      END_STATE();
    case 213:
      if (lookahead == 'c') ADVANCE(156);
      END_STATE();
    case 214:
      if (lookahead == 'c') ADVANCE(158);
      END_STATE();
    case 215:
      if (lookahead == 'c') ADVANCE(660);
      if (lookahead == 'd') ADVANCE(389);
      if (lookahead == 'j') ADVANCE(111);
      if (lookahead == 's') ADVANCE(216);
      if (lookahead == 'v') ADVANCE(410);
      END_STATE();
    case 216:
      if (lookahead == 'c') ADVANCE(689);
      if (lookahead == 't') ADVANCE(143);
      END_STATE();
    case 217:
      if (lookahead == 'c') ADVANCE(395);
      END_STATE();
    case 218:
      if (lookahead == 'c') ADVANCE(91);
      END_STATE();
    case 219:
      if (lookahead == 'c') ADVANCE(672);
      END_STATE();
    case 220:
      if (lookahead == 'c') ADVANCE(729);
      END_STATE();
    case 221:
      if (lookahead == 'c') ADVANCE(681);
      END_STATE();
    case 222:
      if (lookahead == 'c') ADVANCE(731);
      END_STATE();
    case 223:
      if (lookahead == 'c') ADVANCE(687);
      END_STATE();
    case 224:
      if (lookahead == 'c') ADVANCE(688);
      END_STATE();
    case 225:
      if (lookahead == 'c') ADVANCE(690);
      END_STATE();
    case 226:
      if (lookahead == 'c') ADVANCE(691);
      END_STATE();
    case 227:
      if (lookahead == 'c') ADVANCE(692);
      END_STATE();
    case 228:
      if (lookahead == 'c') ADVANCE(951);
      END_STATE();
    case 229:
      if (lookahead == 'd') ADVANCE(1030);
      if (lookahead == 'y') ADVANCE(1069);
      END_STATE();
    case 230:
      if (lookahead == 'd') ADVANCE(838);
      END_STATE();
    case 231:
      if (lookahead == 'd') ADVANCE(432);
      END_STATE();
    case 232:
      if (lookahead == 'd') ADVANCE(1172);
      END_STATE();
    case 233:
      if (lookahead == 'd') ADVANCE(1129);
      END_STATE();
    case 234:
      if (lookahead == 'd') ADVANCE(1211);
      END_STATE();
    case 235:
      if (lookahead == 'd') ADVANCE(1210);
      END_STATE();
    case 236:
      if (lookahead == 'd') ADVANCE(1199);
      END_STATE();
    case 237:
      if (lookahead == 'd') ADVANCE(1200);
      END_STATE();
    case 238:
      if (lookahead == 'd') ADVANCE(1195);
      END_STATE();
    case 239:
      if (lookahead == 'd') ADVANCE(986);
      END_STATE();
    case 240:
      if (lookahead == 'd') ADVANCE(702);
      if (lookahead == 'p') ADVANCE(724);
      if (lookahead == 'r') ADVANCE(515);
      if (lookahead == 'u') ADVANCE(461);
      END_STATE();
    case 241:
      if (lookahead == 'd') ADVANCE(865);
      if (lookahead == 'f') ADVANCE(519);
      if (lookahead == 's') ADVANCE(750);
      END_STATE();
    case 242:
      if (lookahead == 'd') ADVANCE(310);
      END_STATE();
    case 243:
      if (lookahead == 'd') ADVANCE(1014);
      END_STATE();
    case 244:
      if (lookahead == 'd') ADVANCE(758);
      END_STATE();
    case 245:
      if (lookahead == 'd') ADVANCE(630);
      END_STATE();
    case 246:
      if (lookahead == 'd') ADVANCE(464);
      END_STATE();
    case 247:
      if (lookahead == 'd') ADVANCE(93);
      END_STATE();
    case 248:
      if (lookahead == 'd') ADVANCE(281);
      END_STATE();
    case 249:
      if (lookahead == 'd') ADVANCE(706);
      if (lookahead == 'p') ADVANCE(724);
      if (lookahead == 'r') ADVANCE(515);
      if (lookahead == 'u') ADVANCE(461);
      END_STATE();
    case 250:
      if (lookahead == 'd') ADVANCE(283);
      END_STATE();
    case 251:
      if (lookahead == 'd') ADVANCE(833);
      END_STATE();
    case 252:
      if (lookahead == 'd') ADVANCE(292);
      END_STATE();
    case 253:
      if (lookahead == 'd') ADVANCE(293);
      END_STATE();
    case 254:
      if (lookahead == 'd') ADVANCE(294);
      END_STATE();
    case 255:
      if (lookahead == 'd') ADVANCE(295);
      END_STATE();
    case 256:
      if (lookahead == 'd') ADVANCE(302);
      END_STATE();
    case 257:
      if (lookahead == 'd') ADVANCE(303);
      END_STATE();
    case 258:
      if (lookahead == 'd') ADVANCE(304);
      END_STATE();
    case 259:
      if (lookahead == 'd') ADVANCE(844);
      if (lookahead == 'g') ADVANCE(313);
      if (lookahead == 'h') ADVANCE(244);
      if (lookahead == 'l') ADVANCE(308);
      if (lookahead == 'o') ADVANCE(714);
      if (lookahead == 's') ADVANCE(749);
      if (lookahead == 't') ADVANCE(904);
      END_STATE();
    case 260:
      if (lookahead == 'd') ADVANCE(78);
      END_STATE();
    case 261:
      if (lookahead == 'd') ADVANCE(1017);
      END_STATE();
    case 262:
      if (lookahead == 'd') ADVANCE(381);
      END_STATE();
    case 263:
      if (lookahead == 'd') ADVANCE(141);
      END_STATE();
    case 264:
      if (lookahead == 'd') ADVANCE(860);
      if (lookahead == 'g') ADVANCE(400);
      if (lookahead == 's') ADVANCE(776);
      END_STATE();
    case 265:
      if (lookahead == 'd') ADVANCE(366);
      END_STATE();
    case 266:
      if (lookahead == 'd') ADVANCE(373);
      END_STATE();
    case 267:
      if (lookahead == 'd') ADVANCE(376);
      END_STATE();
    case 268:
      if (lookahead == 'd') ADVANCE(95);
      END_STATE();
    case 269:
      if (lookahead == 'd') ADVANCE(874);
      if (lookahead == 's') ADVANCE(811);
      END_STATE();
    case 270:
      if (lookahead == 'd') ADVANCE(98);
      END_STATE();
    case 271:
      if (lookahead == 'd') ADVANCE(409);
      END_STATE();
    case 272:
      if (lookahead == 'e') ADVANCE(1044);
      if (lookahead == 't') ADVANCE(1043);
      END_STATE();
    case 273:
      if (lookahead == 'e') ADVANCE(1042);
      if (lookahead == 'o') ADVANCE(625);
      if (lookahead == 't') ADVANCE(1040);
      END_STATE();
    case 274:
      if (lookahead == 'e') ADVANCE(1039);
      END_STATE();
    case 275:
      if (lookahead == 'e') ADVANCE(1039);
      if (lookahead == 'o') ADVANCE(882);
      END_STATE();
    case 276:
      if (lookahead == 'e') ADVANCE(998);
      END_STATE();
    case 277:
      if (lookahead == 'e') ADVANCE(1075);
      END_STATE();
    case 278:
      if (lookahead == 'e') ADVANCE(1076);
      END_STATE();
    case 279:
      if (lookahead == 'e') ADVANCE(1086);
      END_STATE();
    case 280:
      if (lookahead == 'e') ADVANCE(417);
      END_STATE();
    case 281:
      if (lookahead == 'e') ADVANCE(1109);
      END_STATE();
    case 282:
      if (lookahead == 'e') ADVANCE(1108);
      END_STATE();
    case 283:
      if (lookahead == 'e') ADVANCE(1064);
      END_STATE();
    case 284:
      if (lookahead == 'e') ADVANCE(1125);
      END_STATE();
    case 285:
      if (lookahead == 'e') ADVANCE(1112);
      END_STATE();
    case 286:
      if (lookahead == 'e') ADVANCE(739);
      END_STATE();
    case 287:
      if (lookahead == 'e') ADVANCE(1157);
      END_STATE();
    case 288:
      if (lookahead == 'e') ADVANCE(1104);
      END_STATE();
    case 289:
      if (lookahead == 'e') ADVANCE(1060);
      END_STATE();
    case 290:
      if (lookahead == 'e') ADVANCE(1103);
      END_STATE();
    case 291:
      if (lookahead == 'e') ADVANCE(1107);
      END_STATE();
    case 292:
      if (lookahead == 'e') ADVANCE(1141);
      END_STATE();
    case 293:
      if (lookahead == 'e') ADVANCE(1120);
      END_STATE();
    case 294:
      if (lookahead == 'e') ADVANCE(1140);
      END_STATE();
    case 295:
      if (lookahead == 'e') ADVANCE(1143);
      END_STATE();
    case 296:
      if (lookahead == 'e') ADVANCE(1144);
      END_STATE();
    case 297:
      if (lookahead == 'e') ADVANCE(1171);
      END_STATE();
    case 298:
      if (lookahead == 'e') ADVANCE(1170);
      END_STATE();
    case 299:
      if (lookahead == 'e') ADVANCE(1119);
      END_STATE();
    case 300:
      if (lookahead == 'e') ADVANCE(1101);
      END_STATE();
    case 301:
      if (lookahead == 'e') ADVANCE(1156);
      END_STATE();
    case 302:
      if (lookahead == 'e') ADVANCE(1121);
      END_STATE();
    case 303:
      if (lookahead == 'e') ADVANCE(1147);
      END_STATE();
    case 304:
      if (lookahead == 'e') ADVANCE(1148);
      END_STATE();
    case 305:
      if (lookahead == 'e') ADVANCE(1197);
      END_STATE();
    case 306:
      if (lookahead == 'e') ADVANCE(1041);
      if (lookahead == 'o') ADVANCE(625);
      if (lookahead == 't') ADVANCE(1040);
      END_STATE();
    case 307:
      if (lookahead == 'e') ADVANCE(1022);
      END_STATE();
    case 308:
      if (lookahead == 'e') ADVANCE(565);
      END_STATE();
    case 309:
      if (lookahead == 'e') ADVANCE(845);
      END_STATE();
    case 310:
      if (lookahead == 'e') ADVANCE(219);
      END_STATE();
    case 311:
      if (lookahead == 'e') ADVANCE(429);
      END_STATE();
    case 312:
      if (lookahead == 'e') ADVANCE(742);
      END_STATE();
    case 313:
      if (lookahead == 'e') ADVANCE(637);
      END_STATE();
    case 314:
      if (lookahead == 'e') ADVANCE(1003);
      END_STATE();
    case 315:
      if (lookahead == 'e') ADVANCE(989);
      END_STATE();
    case 316:
      if (lookahead == 'e') ADVANCE(743);
      END_STATE();
    case 317:
      if (lookahead == 'e') ADVANCE(247);
      END_STATE();
    case 318:
      if (lookahead == 'e') ADVANCE(815);
      END_STATE();
    case 319:
      if (lookahead == 'e') ADVANCE(438);
      END_STATE();
    case 320:
      if (lookahead == 'e') ADVANCE(752);
      END_STATE();
    case 321:
      if (lookahead == 'e') ADVANCE(587);
      END_STATE();
    case 322:
      if (lookahead == 'e') ADVANCE(232);
      END_STATE();
    case 323:
      if (lookahead == 'e') ADVANCE(968);
      END_STATE();
    case 324:
      if (lookahead == 'e') ADVANCE(588);
      END_STATE();
    case 325:
      if (lookahead == 'e') ADVANCE(64);
      END_STATE();
    case 326:
      if (lookahead == 'e') ADVANCE(47);
      END_STATE();
    case 327:
      if (lookahead == 'e') ADVANCE(122);
      END_STATE();
    case 328:
      if (lookahead == 'e') ADVANCE(49);
      END_STATE();
    case 329:
      if (lookahead == 'e') ADVANCE(760);
      END_STATE();
    case 330:
      if (lookahead == 'e') ADVANCE(818);
      END_STATE();
    case 331:
      if (lookahead == 'e') ADVANCE(764);
      END_STATE();
    case 332:
      if (lookahead == 'e') ADVANCE(11);
      END_STATE();
    case 333:
      if (lookahead == 'e') ADVANCE(234);
      END_STATE();
    case 334:
      if (lookahead == 'e') ADVANCE(203);
      END_STATE();
    case 335:
      if (lookahead == 'e') ADVANCE(805);
      END_STATE();
    case 336:
      if (lookahead == 'e') ADVANCE(46);
      END_STATE();
    case 337:
      if (lookahead == 'e') ADVANCE(567);
      END_STATE();
    case 338:
      if (lookahead == 'e') ADVANCE(235);
      END_STATE();
    case 339:
      if (lookahead == 'e') ADVANCE(715);
      END_STATE();
    case 340:
      if (lookahead == 'e') ADVANCE(236);
      END_STATE();
    case 341:
      if (lookahead == 'e') ADVANCE(814);
      END_STATE();
    case 342:
      if (lookahead == 'e') ADVANCE(187);
      END_STATE();
    case 343:
      if (lookahead == 'e') ADVANCE(237);
      END_STATE();
    case 344:
      if (lookahead == 'e') ADVANCE(188);
      END_STATE();
    case 345:
      if (lookahead == 'e') ADVANCE(751);
      END_STATE();
    case 346:
      if (lookahead == 'e') ADVANCE(238);
      END_STATE();
    case 347:
      if (lookahead == 'e') ADVANCE(906);
      END_STATE();
    case 348:
      if (lookahead == 'e') ADVANCE(820);
      END_STATE();
    case 349:
      if (lookahead == 'e') ADVANCE(745);
      END_STATE();
    case 350:
      if (lookahead == 'e') ADVANCE(744);
      END_STATE();
    case 351:
      if (lookahead == 'e') ADVANCE(825);
      END_STATE();
    case 352:
      if (lookahead == 'e') ADVANCE(772);
      END_STATE();
    case 353:
      if (lookahead == 'e') ADVANCE(826);
      END_STATE();
    case 354:
      if (lookahead == 'e') ADVANCE(786);
      END_STATE();
    case 355:
      if (lookahead == 'e') ADVANCE(827);
      END_STATE();
    case 356:
      if (lookahead == 'e') ADVANCE(38);
      END_STATE();
    case 357:
      if (lookahead == 'e') ADVANCE(828);
      END_STATE();
    case 358:
      if (lookahead == 'e') ADVANCE(852);
      END_STATE();
    case 359:
      if (lookahead == 'e') ADVANCE(829);
      END_STATE();
    case 360:
      if (lookahead == 'e') ADVANCE(775);
      END_STATE();
    case 361:
      if (lookahead == 'e') ADVANCE(830);
      END_STATE();
    case 362:
      if (lookahead == 'e') ADVANCE(912);
      END_STATE();
    case 363:
      if (lookahead == 'e') ADVANCE(831);
      END_STATE();
    case 364:
      if (lookahead == 'e') ADVANCE(564);
      if (lookahead == 'o') ADVANCE(625);
      END_STATE();
    case 365:
      if (lookahead == 'e') ADVANCE(832);
      END_STATE();
    case 366:
      if (lookahead == 'e') ADVANCE(778);
      END_STATE();
    case 367:
      if (lookahead == 'e') ADVANCE(893);
      END_STATE();
    case 368:
      if (lookahead == 'e') ADVANCE(834);
      END_STATE();
    case 369:
      if (lookahead == 'e') ADVANCE(905);
      END_STATE();
    case 370:
      if (lookahead == 'e') ADVANCE(835);
      END_STATE();
    case 371:
      if (lookahead == 'e') ADVANCE(836);
      END_STATE();
    case 372:
      if (lookahead == 'e') ADVANCE(322);
      END_STATE();
    case 373:
      if (lookahead == 'e') ADVANCE(780);
      END_STATE();
    case 374:
      if (lookahead == 'e') ADVANCE(761);
      END_STATE();
    case 375:
      if (lookahead == 'e') ADVANCE(765);
      END_STATE();
    case 376:
      if (lookahead == 'e') ADVANCE(789);
      END_STATE();
    case 377:
      if (lookahead == 'e') ADVANCE(50);
      END_STATE();
    case 378:
      if (lookahead == 'e') ADVANCE(155);
      END_STATE();
    case 379:
      if (lookahead == 'e') ADVANCE(623);
      END_STATE();
    case 380:
      if (lookahead == 'e') ADVANCE(924);
      END_STATE();
    case 381:
      if (lookahead == 'e') ADVANCE(268);
      END_STATE();
    case 382:
      if (lookahead == 'e') ADVANCE(728);
      END_STATE();
    case 383:
      if (lookahead == 'e') ADVANCE(595);
      END_STATE();
    case 384:
      if (lookahead == 'e') ADVANCE(130);
      END_STATE();
    case 385:
      if (lookahead == 'e') ADVANCE(134);
      END_STATE();
    case 386:
      if (lookahead == 'e') ADVANCE(260);
      END_STATE();
    case 387:
      if (lookahead == 'e') ADVANCE(597);
      END_STATE();
    case 388:
      if (lookahead == 'e') ADVANCE(598);
      END_STATE();
    case 389:
      if (lookahead == 'e') ADVANCE(935);
      END_STATE();
    case 390:
      if (lookahead == 'e') ADVANCE(867);
      END_STATE();
    case 391:
      if (lookahead == 'e') ADVANCE(556);
      END_STATE();
    case 392:
      if (lookahead == 'e') ADVANCE(599);
      END_STATE();
    case 393:
      if (lookahead == 'e') ADVANCE(855);
      END_STATE();
    case 394:
      if (lookahead == 'e') ADVANCE(601);
      END_STATE();
    case 395:
      if (lookahead == 'e') ADVANCE(793);
      END_STATE();
    case 396:
      if (lookahead == 'e') ADVANCE(857);
      END_STATE();
    case 397:
      if (lookahead == 'e') ADVANCE(859);
      END_STATE();
    case 398:
      if (lookahead == 'e') ADVANCE(861);
      END_STATE();
    case 399:
      if (lookahead == 'e') ADVANCE(558);
      END_STATE();
    case 400:
      if (lookahead == 'e') ADVANCE(667);
      END_STATE();
    case 401:
      if (lookahead == 'e') ADVANCE(809);
      END_STATE();
    case 402:
      if (lookahead == 'e') ADVANCE(85);
      END_STATE();
    case 403:
      if (lookahead == 'e') ADVANCE(164);
      END_STATE();
    case 404:
      if (lookahead == 'e') ADVANCE(168);
      END_STATE();
    case 405:
      if (lookahead == 'e') ADVANCE(418);
      END_STATE();
    case 406:
      if (lookahead == 'e') ADVANCE(439);
      END_STATE();
    case 407:
      if (lookahead == 'e') ADVANCE(270);
      END_STATE();
    case 408:
      if (lookahead == 'e') ADVANCE(228);
      END_STATE();
    case 409:
      if (lookahead == 'e') ADVANCE(954);
      END_STATE();
    case 410:
      if (lookahead == 'e') ADVANCE(813);
      END_STATE();
    case 411:
      if (lookahead == 'f') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(563);
      END_STATE();
    case 412:
      if (lookahead == 'f') ADVANCE(34);
      END_STATE();
    case 413:
      if (lookahead == 'f') ADVANCE(21);
      if (lookahead == 'o') ADVANCE(563);
      END_STATE();
    case 414:
      if (lookahead == 'f') ADVANCE(648);
      END_STATE();
    case 415:
      if (lookahead == 'f') ADVANCE(25);
      if (lookahead == 'o') ADVANCE(616);
      END_STATE();
    case 416:
      if (lookahead == 'f') ADVANCE(474);
      END_STATE();
    case 417:
      if (lookahead == 'f') ADVANCE(335);
      if (lookahead == 'q') ADVANCE(965);
      if (lookahead == 's') ADVANCE(734);
      END_STATE();
    case 418:
      if (lookahead == 'f') ADVANCE(335);
      if (lookahead == 'q') ADVANCE(983);
      if (lookahead == 's') ADVANCE(735);
      END_STATE();
    case 419:
      if (lookahead == 'f') ADVANCE(481);
      END_STATE();
    case 420:
      if (lookahead == 'f') ADVANCE(659);
      END_STATE();
    case 421:
      if (lookahead == 'f') ADVANCE(661);
      if (lookahead == 'm') ADVANCE(492);
      if (lookahead == 'r') ADVANCE(121);
      END_STATE();
    case 422:
      if (lookahead == 'f') ADVANCE(661);
      if (lookahead == 'm') ADVANCE(492);
      if (lookahead == 'r') ADVANCE(121);
      if (lookahead == 's') ADVANCE(463);
      if (lookahead == 't') ADVANCE(798);
      END_STATE();
    case 423:
      if (lookahead == 'f') ADVANCE(984);
      if (lookahead == 'u') ADVANCE(769);
      END_STATE();
    case 424:
      if (lookahead == 'f') ADVANCE(500);
      END_STATE();
    case 425:
      if (lookahead == 'g') ADVANCE(1062);
      END_STATE();
    case 426:
      if (lookahead == 'g') ADVANCE(1209);
      END_STATE();
    case 427:
      if (lookahead == 'g') ADVANCE(1058);
      END_STATE();
    case 428:
      if (lookahead == 'g') ADVANCE(276);
      if (lookahead == 'm') ADVANCE(626);
      END_STATE();
    case 429:
      if (lookahead == 'g') ADVANCE(488);
      END_STATE();
    case 430:
      if (lookahead == 'g') ADVANCE(982);
      END_STATE();
    case 431:
      if (lookahead == 'g') ADVANCE(817);
      END_STATE();
    case 432:
      if (lookahead == 'g') ADVANCE(377);
      END_STATE();
    case 433:
      if (lookahead == 'g') ADVANCE(822);
      END_STATE();
    case 434:
      if (lookahead == 'g') ADVANCE(824);
      END_STATE();
    case 435:
      if (lookahead == 'g') ADVANCE(391);
      END_STATE();
    case 436:
      if (lookahead == 'g') ADVANCE(368);
      END_STATE();
    case 437:
      if (lookahead == 'g') ADVANCE(387);
      END_STATE();
    case 438:
      if (lookahead == 'g') ADVANCE(662);
      END_STATE();
    case 439:
      if (lookahead == 'g') ADVANCE(489);
      END_STATE();
    case 440:
      if (lookahead == 'g') ADVANCE(399);
      END_STATE();
    case 441:
      if (lookahead == 'h') ADVANCE(1067);
      END_STATE();
    case 442:
      if (lookahead == 'h') ADVANCE(1068);
      END_STATE();
    case 443:
      if (lookahead == 'h') ADVANCE(1206);
      END_STATE();
    case 444:
      if (lookahead == 'h') ADVANCE(1131);
      END_STATE();
    case 445:
      if (lookahead == 'h') ADVANCE(1151);
      END_STATE();
    case 446:
      if (lookahead == 'h') ADVANCE(1153);
      END_STATE();
    case 447:
      if (lookahead == 'h') ADVANCE(766);
      if (lookahead == 'l') ADVANCE(841);
      END_STATE();
    case 448:
      if (lookahead == 'h') ADVANCE(318);
      END_STATE();
    case 449:
      if (lookahead == 'h') ADVANCE(137);
      END_STATE();
    case 450:
      if (lookahead == 'h') ADVANCE(646);
      END_STATE();
    case 451:
      if (lookahead == 'h') ADVANCE(35);
      END_STATE();
    case 452:
      if (lookahead == 'h') ADVANCE(939);
      END_STATE();
    case 453:
      if (lookahead == 'h') ADVANCE(403);
      END_STATE();
    case 454:
      if (lookahead == 'i') ADVANCE(700);
      if (lookahead == 's') ADVANCE(513);
      if (lookahead == 't') ADVANCE(117);
      END_STATE();
    case 455:
      if (lookahead == 'i') ADVANCE(1023);
      END_STATE();
    case 456:
      if (lookahead == 'i') ADVANCE(1130);
      END_STATE();
    case 457:
      if (lookahead == 'i') ADVANCE(1105);
      END_STATE();
    case 458:
      if (lookahead == 'i') ADVANCE(1150);
      END_STATE();
    case 459:
      if (lookahead == 'i') ADVANCE(1128);
      END_STATE();
    case 460:
      if (lookahead == 'i') ADVANCE(1149);
      END_STATE();
    case 461:
      if (lookahead == 'i') ADVANCE(239);
      END_STATE();
    case 462:
      if (lookahead == 'i') ADVANCE(416);
      END_STATE();
    case 463:
      if (lookahead == 'i') ADVANCE(1021);
      END_STATE();
    case 464:
      if (lookahead == 'i') ADVANCE(988);
      END_STATE();
    case 465:
      if (lookahead == 'i') ADVANCE(586);
      END_STATE();
    case 466:
      if (lookahead == 'i') ADVANCE(324);
      END_STATE();
    case 467:
      if (lookahead == 'i') ADVANCE(578);
      END_STATE();
    case 468:
      if (lookahead == 'i') ADVANCE(710);
      END_STATE();
    case 469:
      if (lookahead == 'i') ADVANCE(898);
      END_STATE();
    case 470:
      if (lookahead == 'i') ADVANCE(218);
      END_STATE();
    case 471:
      if (lookahead == 'i') ADVANCE(704);
      if (lookahead == 'p') ADVANCE(684);
      END_STATE();
    case 472:
      if (lookahead == 'i') ADVANCE(900);
      if (lookahead == 'o') ADVANCE(980);
      END_STATE();
    case 473:
      if (lookahead == 'i') ADVANCE(571);
      END_STATE();
    case 474:
      if (lookahead == 'i') ADVANCE(317);
      END_STATE();
    case 475:
      if (lookahead == 'i') ADVANCE(899);
      END_STATE();
    case 476:
      if (lookahead == 'i') ADVANCE(879);
      END_STATE();
    case 477:
      if (lookahead == 'i') ADVANCE(582);
      END_STATE();
    case 478:
      if (lookahead == 'i') ADVANCE(284);
      END_STATE();
    case 479:
      if (lookahead == 'i') ADVANCE(341);
      END_STATE();
    case 480:
      if (lookahead == 'i') ADVANCE(348);
      END_STATE();
    case 481:
      if (lookahead == 'i') ADVANCE(343);
      END_STATE();
    case 482:
      if (lookahead == 'i') ADVANCE(251);
      END_STATE();
    case 483:
      if (lookahead == 'i') ADVANCE(545);
      END_STATE();
    case 484:
      if (lookahead == 'i') ADVANCE(590);
      END_STATE();
    case 485:
      if (lookahead == 'i') ADVANCE(383);
      END_STATE();
    case 486:
      if (lookahead == 'i') ADVANCE(719);
      END_STATE();
    case 487:
      if (lookahead == 'i') ADVANCE(608);
      END_STATE();
    case 488:
      if (lookahead == 'i') ADVANCE(650);
      END_STATE();
    case 489:
      if (lookahead == 'i') ADVANCE(651);
      END_STATE();
    case 490:
      if (lookahead == 'i') ADVANCE(559);
      END_STATE();
    case 491:
      if (lookahead == 'i') ADVANCE(652);
      END_STATE();
    case 492:
      if (lookahead == 'i') ADVANCE(548);
      END_STATE();
    case 493:
      if (lookahead == 'i') ADVANCE(673);
      END_STATE();
    case 494:
      if (lookahead == 'i') ADVANCE(683);
      END_STATE();
    case 495:
      if (lookahead == 'i') ADVANCE(654);
      END_STATE();
    case 496:
      if (lookahead == 'i') ADVANCE(655);
      END_STATE();
    case 497:
      if (lookahead == 'i') ADVANCE(656);
      END_STATE();
    case 498:
      if (lookahead == 'i') ADVANCE(419);
      END_STATE();
    case 499:
      if (lookahead == 'i') ADVANCE(876);
      END_STATE();
    case 500:
      if (lookahead == 'i') ADVANCE(407);
      END_STATE();
    case 501:
      if (lookahead == 'i') ADVANCE(424);
      END_STATE();
    case 502:
      if (lookahead == 'i') ADVANCE(880);
      END_STATE();
    case 503:
      if (lookahead == 'j') ADVANCE(866);
      END_STATE();
    case 504:
      if (lookahead == 'j') ADVANCE(110);
      END_STATE();
    case 505:
      if (lookahead == 'k') ADVANCE(1202);
      END_STATE();
    case 506:
      if (lookahead == 'k') ADVANCE(960);
      END_STATE();
    case 507:
      if (lookahead == 'k') ADVANCE(340);
      END_STATE();
    case 508:
      if (lookahead == 'k') ADVANCE(478);
      END_STATE();
    case 509:
      if (lookahead == 'k') ADVANCE(329);
      END_STATE();
    case 510:
      if (lookahead == 'k') ADVANCE(480);
      END_STATE();
    case 511:
      if (lookahead == 'l') ADVANCE(512);
      if (lookahead == 'n') ADVANCE(229);
      END_STATE();
    case 512:
      if (lookahead == 'l') ADVANCE(1070);
      END_STATE();
    case 513:
      if (lookahead == 'l') ADVANCE(1193);
      END_STATE();
    case 514:
      if (lookahead == 'l') ADVANCE(1113);
      END_STATE();
    case 515:
      if (lookahead == 'l') ADVANCE(72);
      END_STATE();
    case 516:
      if (lookahead == 'l') ADVANCE(466);
      if (lookahead == 'o') ADVANCE(520);
      END_STATE();
    case 517:
      if (lookahead == 'l') ADVANCE(839);
      END_STATE();
    case 518:
      if (lookahead == 'l') ADVANCE(995);
      END_STATE();
    case 519:
      if (lookahead == 'l') ADVANCE(115);
      END_STATE();
    case 520:
      if (lookahead == 'l') ADVANCE(636);
      END_STATE();
    case 521:
      if (lookahead == 'l') ADVANCE(126);
      END_STATE();
    case 522:
      if (lookahead == 'l') ADVANCE(457);
      END_STATE();
    case 523:
      if (lookahead == 'l') ADVANCE(337);
      END_STATE();
    case 524:
      if (lookahead == 'l') ADVANCE(83);
      END_STATE();
    case 525:
      if (lookahead == 'l') ADVANCE(524);
      END_STATE();
    case 526:
      if (lookahead == 'l') ADVANCE(138);
      END_STATE();
    case 527:
      if (lookahead == 'l') ADVANCE(973);
      END_STATE();
    case 528:
      if (lookahead == 'l') ADVANCE(974);
      END_STATE();
    case 529:
      if (lookahead == 'l') ADVANCE(975);
      END_STATE();
    case 530:
      if (lookahead == 'l') ADVANCE(976);
      END_STATE();
    case 531:
      if (lookahead == 'l') ADVANCE(977);
      END_STATE();
    case 532:
      if (lookahead == 'l') ADVANCE(485);
      END_STATE();
    case 533:
      if (lookahead == 'l') ADVANCE(88);
      END_STATE();
    case 534:
      if (lookahead == 'l') ADVANCE(533);
      END_STATE();
    case 535:
      if (lookahead == 'l') ADVANCE(101);
      END_STATE();
    case 536:
      if (lookahead == 'm') ADVANCE(1100);
      END_STATE();
    case 537:
      if (lookahead == 'm') ADVANCE(1178);
      END_STATE();
    case 538:
      if (lookahead == 'm') ADVANCE(132);
      END_STATE();
    case 539:
      if (lookahead == 'm') ADVANCE(703);
      END_STATE();
    case 540:
      if (lookahead == 'm') ADVANCE(455);
      END_STATE();
    case 541:
      if (lookahead == 'm') ADVANCE(718);
      END_STATE();
    case 542:
      if (lookahead == 'm') ADVANCE(94);
      END_STATE();
    case 543:
      if (lookahead == 'm') ADVANCE(707);
      END_STATE();
    case 544:
      if (lookahead == 'm') ADVANCE(326);
      END_STATE();
    case 545:
      if (lookahead == 'm') ADVANCE(307);
      END_STATE();
    case 546:
      if (lookahead == 'm') ADVANCE(287);
      END_STATE();
    case 547:
      if (lookahead == 'm') ADVANCE(296);
      END_STATE();
    case 548:
      if (lookahead == 'm') ADVANCE(298);
      END_STATE();
    case 549:
      if (lookahead == 'm') ADVANCE(351);
      END_STATE();
    case 550:
      if (lookahead == 'm') ADVANCE(355);
      END_STATE();
    case 551:
      if (lookahead == 'm') ADVANCE(357);
      END_STATE();
    case 552:
      if (lookahead == 'm') ADVANCE(359);
      END_STATE();
    case 553:
      if (lookahead == 'm') ADVANCE(370);
      END_STATE();
    case 554:
      if (lookahead == 'm') ADVANCE(86);
      END_STATE();
    case 555:
      if (lookahead == 'm') ADVANCE(362);
      END_STATE();
    case 556:
      if (lookahead == 'm') ADVANCE(388);
      END_STATE();
    case 557:
      if (lookahead == 'm') ADVANCE(862);
      if (lookahead == 's') ADVANCE(342);
      END_STATE();
    case 558:
      if (lookahead == 'm') ADVANCE(394);
      END_STATE();
    case 559:
      if (lookahead == 'm') ADVANCE(397);
      END_STATE();
    case 560:
      if (lookahead == 'm') ADVANCE(172);
      END_STATE();
    case 561:
      if (lookahead == 'n') ADVANCE(230);
      END_STATE();
    case 562:
      if (lookahead == 'n') ADVANCE(230);
      if (lookahead == 'q') ADVANCE(1038);
      END_STATE();
    case 563:
      if (lookahead == 'n') ADVANCE(207);
      END_STATE();
    case 564:
      if (lookahead == 'n') ADVANCE(1066);
      END_STATE();
    case 565:
      if (lookahead == 'n') ADVANCE(1111);
      END_STATE();
    case 566:
      if (lookahead == 'n') ADVANCE(1086);
      END_STATE();
    case 567:
      if (lookahead == 'n') ADVANCE(1110);
      END_STATE();
    case 568:
      if (lookahead == 'n') ADVANCE(1138);
      END_STATE();
    case 569:
      if (lookahead == 'n') ADVANCE(1142);
      END_STATE();
    case 570:
      if (lookahead == 'n') ADVANCE(1204);
      END_STATE();
    case 571:
      if (lookahead == 'n') ADVANCE(1205);
      END_STATE();
    case 572:
      if (lookahead == 'n') ADVANCE(1208);
      END_STATE();
    case 573:
      if (lookahead == 'n') ADVANCE(1158);
      END_STATE();
    case 574:
      if (lookahead == 'n') ADVANCE(1135);
      END_STATE();
    case 575:
      if (lookahead == 'n') ADVANCE(1192);
      END_STATE();
    case 576:
      if (lookahead == 'n') ADVANCE(1132);
      END_STATE();
    case 577:
      if (lookahead == 'n') ADVANCE(1013);
      END_STATE();
    case 578:
      if (lookahead == 'n') ADVANCE(425);
      END_STATE();
    case 579:
      if (lookahead == 'n') ADVANCE(639);
      END_STATE();
    case 580:
      if (lookahead == 'n') ADVANCE(245);
      END_STATE();
    case 581:
      if (lookahead == 'n') ADVANCE(959);
      END_STATE();
    case 582:
      if (lookahead == 'n') ADVANCE(427);
      END_STATE();
    case 583:
      if (lookahead == 'n') ADVANCE(120);
      END_STATE();
    case 584:
      if (lookahead == 'n') ADVANCE(147);
      END_STATE();
    case 585:
      if (lookahead == 'n') ADVANCE(430);
      END_STATE();
    case 586:
      if (lookahead == 'n') ADVANCE(816);
      END_STATE();
    case 587:
      if (lookahead == 'n') ADVANCE(79);
      END_STATE();
    case 588:
      if (lookahead == 'n') ADVANCE(910);
      END_STATE();
    case 589:
      if (lookahead == 'n') ADVANCE(347);
      END_STATE();
    case 590:
      if (lookahead == 'n') ADVANCE(81);
      END_STATE();
    case 591:
      if (lookahead == 'n') ADVANCE(37);
      END_STATE();
    case 592:
      if (lookahead == 'n') ADVANCE(66);
      END_STATE();
    case 593:
      if (lookahead == 'n') ADVANCE(87);
      END_STATE();
    case 594:
      if (lookahead == 'n') ADVANCE(80);
      END_STATE();
    case 595:
      if (lookahead == 'n') ADVANCE(921);
      END_STATE();
    case 596:
      if (lookahead == 'n') ADVANCE(944);
      if (lookahead == 'u') ADVANCE(609);
      END_STATE();
    case 597:
      if (lookahead == 'n') ADVANCE(892);
      END_STATE();
    case 598:
      if (lookahead == 'n') ADVANCE(922);
      END_STATE();
    case 599:
      if (lookahead == 'n') ADVANCE(894);
      END_STATE();
    case 600:
      if (lookahead == 'n') ADVANCE(336);
      END_STATE();
    case 601:
      if (lookahead == 'n') ADVANCE(931);
      END_STATE();
    case 602:
      if (lookahead == 'n') ADVANCE(301);
      END_STATE();
    case 603:
      if (lookahead == 'n') ADVANCE(854);
      END_STATE();
    case 604:
      if (lookahead == 'n') ADVANCE(152);
      if (lookahead == 'r') ADVANCE(406);
      END_STATE();
    case 605:
      if (lookahead == 'n') ADVANCE(926);
      END_STATE();
    case 606:
      if (lookahead == 'n') ADVANCE(858);
      END_STATE();
    case 607:
      if (lookahead == 'n') ADVANCE(927);
      END_STATE();
    case 608:
      if (lookahead == 'n') ADVANCE(392);
      END_STATE();
    case 609:
      if (lookahead == 'n') ADVANCE(932);
      END_STATE();
    case 610:
      if (lookahead == 'n') ADVANCE(864);
      END_STATE();
    case 611:
      if (lookahead == 'n') ADVANCE(213);
      END_STATE();
    case 612:
      if (lookahead == 'n') ADVANCE(157);
      END_STATE();
    case 613:
      if (lookahead == 'n') ADVANCE(214);
      END_STATE();
    case 614:
      if (lookahead == 'n') ADVANCE(159);
      if (lookahead == 't') ADVANCE(812);
      if (lookahead == 'v') ADVANCE(133);
      END_STATE();
    case 615:
      if (lookahead == 'n') ADVANCE(159);
      if (lookahead == 'v') ADVANCE(133);
      END_STATE();
    case 616:
      if (lookahead == 'n') ADVANCE(206);
      END_STATE();
    case 617:
      if (lookahead == 'n') ADVANCE(160);
      if (lookahead == 'v') ADVANCE(165);
      END_STATE();
    case 618:
      if (lookahead == 'n') ADVANCE(161);
      if (lookahead == 'v') ADVANCE(169);
      END_STATE();
    case 619:
      if (lookahead == 'n') ADVANCE(495);
      END_STATE();
    case 620:
      if (lookahead == 'n') ADVANCE(162);
      if (lookahead == 'v') ADVANCE(170);
      END_STATE();
    case 621:
      if (lookahead == 'n') ADVANCE(163);
      if (lookahead == 'v') ADVANCE(171);
      END_STATE();
    case 622:
      if (lookahead == 'n') ADVANCE(167);
      END_STATE();
    case 623:
      if (lookahead == 'n') ADVANCE(877);
      END_STATE();
    case 624:
      if (lookahead == 'n') ADVANCE(105);
      END_STATE();
    case 625:
      if (lookahead == 'o') ADVANCE(506);
      if (lookahead == 'w') ADVANCE(312);
      END_STATE();
    case 626:
      if (lookahead == 'o') ADVANCE(987);
      END_STATE();
    case 627:
      if (lookahead == 'o') ADVANCE(596);
      END_STATE();
    case 628:
      if (lookahead == 'o') ADVANCE(741);
      END_STATE();
    case 629:
      if (lookahead == 'o') ADVANCE(1002);
      END_STATE();
    case 630:
      if (lookahead == 'o') ADVANCE(554);
      END_STATE();
    case 631:
      if (lookahead == 'o') ADVANCE(963);
      END_STATE();
    case 632:
      if (lookahead == 'o') ADVANCE(508);
      END_STATE();
    case 633:
      if (lookahead == 'o') ADVANCE(882);
      END_STATE();
    case 634:
      if (lookahead == 'o') ADVANCE(520);
      END_STATE();
    case 635:
      if (lookahead == 'o') ADVANCE(507);
      END_STATE();
    case 636:
      if (lookahead == 'o') ADVANCE(8);
      END_STATE();
    case 637:
      if (lookahead == 'o') ADVANCE(468);
      END_STATE();
    case 638:
      if (lookahead == 'o') ADVANCE(1000);
      END_STATE();
    case 639:
      if (lookahead == 'o') ADVANCE(577);
      END_STATE();
    case 640:
      if (lookahead == 'o') ADVANCE(903);
      END_STATE();
    case 641:
      if (lookahead == 'o') ADVANCE(748);
      END_STATE();
    case 642:
      if (lookahead == 'o') ADVANCE(243);
      END_STATE();
    case 643:
      if (lookahead == 'o') ADVANCE(632);
      END_STATE();
    case 644:
      if (lookahead == 'o') ADVANCE(908);
      END_STATE();
    case 645:
      if (lookahead == 'o') ADVANCE(603);
      END_STATE();
    case 646:
      if (lookahead == 'o') ADVANCE(233);
      END_STATE();
    case 647:
      if (lookahead == 'o') ADVANCE(99);
      END_STATE();
    case 648:
      if (lookahead == 'o') ADVANCE(808);
      END_STATE();
    case 649:
      if (lookahead == 'o') ADVANCE(624);
      END_STATE();
    case 650:
      if (lookahead == 'o') ADVANCE(569);
      END_STATE();
    case 651:
      if (lookahead == 'o') ADVANCE(573);
      END_STATE();
    case 652:
      if (lookahead == 'o') ADVANCE(574);
      END_STATE();
    case 653:
      if (lookahead == 'o') ADVANCE(891);
      END_STATE();
    case 654:
      if (lookahead == 'o') ADVANCE(575);
      END_STATE();
    case 655:
      if (lookahead == 'o') ADVANCE(591);
      END_STATE();
    case 656:
      if (lookahead == 'o') ADVANCE(576);
      END_STATE();
    case 657:
      if (lookahead == 'o') ADVANCE(777);
      END_STATE();
    case 658:
      if (lookahead == 'o') ADVANCE(925);
      END_STATE();
    case 659:
      if (lookahead == 'o') ADVANCE(747);
      END_STATE();
    case 660:
      if (lookahead == 'o') ADVANCE(810);
      END_STATE();
    case 661:
      if (lookahead == 'o') ADVANCE(757);
      END_STATE();
    case 662:
      if (lookahead == 'o') ADVANCE(763);
      END_STATE();
    case 663:
      if (lookahead == 'o') ADVANCE(807);
      END_STATE();
    case 664:
      if (lookahead == 'o') ADVANCE(896);
      END_STATE();
    case 665:
      if (lookahead == 'o') ADVANCE(781);
      END_STATE();
    case 666:
      if (lookahead == 'o') ADVANCE(248);
      END_STATE();
    case 667:
      if (lookahead == 'o') ADVANCE(486);
      END_STATE();
    case 668:
      if (lookahead == 'o') ADVANCE(600);
      END_STATE();
    case 669:
      if (lookahead == 'o') ADVANCE(261);
      END_STATE();
    case 670:
      if (lookahead == 'o') ADVANCE(783);
      END_STATE();
    case 671:
      if (lookahead == 'o') ADVANCE(847);
      END_STATE();
    case 672:
      if (lookahead == 'o') ADVANCE(250);
      END_STATE();
    case 673:
      if (lookahead == 'o') ADVANCE(592);
      END_STATE();
    case 674:
      if (lookahead == 'o') ADVANCE(784);
      END_STATE();
    case 675:
      if (lookahead == 'o') ADVANCE(850);
      END_STATE();
    case 676:
      if (lookahead == 'o') ADVANCE(602);
      END_STATE();
    case 677:
      if (lookahead == 'o') ADVANCE(722);
      END_STATE();
    case 678:
      if (lookahead == 'o') ADVANCE(972);
      END_STATE();
    case 679:
      if (lookahead == 'o') ADVANCE(785);
      END_STATE();
    case 680:
      if (lookahead == 'o') ADVANCE(853);
      END_STATE();
    case 681:
      if (lookahead == 'o') ADVANCE(252);
      END_STATE();
    case 682:
      if (lookahead == 'o') ADVANCE(788);
      END_STATE();
    case 683:
      if (lookahead == 'o') ADVANCE(594);
      END_STATE();
    case 684:
      if (lookahead == 'o') ADVANCE(790);
      END_STATE();
    case 685:
      if (lookahead == 'o') ADVANCE(253);
      END_STATE();
    case 686:
      if (lookahead == 'o') ADVANCE(791);
      END_STATE();
    case 687:
      if (lookahead == 'o') ADVANCE(254);
      END_STATE();
    case 688:
      if (lookahead == 'o') ADVANCE(255);
      END_STATE();
    case 689:
      if (lookahead == 'o') ADVANCE(794);
      END_STATE();
    case 690:
      if (lookahead == 'o') ADVANCE(256);
      END_STATE();
    case 691:
      if (lookahead == 'o') ADVANCE(257);
      END_STATE();
    case 692:
      if (lookahead == 'o') ADVANCE(258);
      END_STATE();
    case 693:
      if (lookahead == 'o') ADVANCE(510);
      END_STATE();
    case 694:
      if (lookahead == 'o') ADVANCE(693);
      END_STATE();
    case 695:
      if (lookahead == 'o') ADVANCE(606);
      END_STATE();
    case 696:
      if (lookahead == 'o') ADVANCE(610);
      END_STATE();
    case 697:
      if (lookahead == 'o') ADVANCE(103);
      END_STATE();
    case 698:
      if (lookahead == 'o') ADVANCE(104);
      END_STATE();
    case 699:
      if (lookahead == 'o') ADVANCE(956);
      END_STATE();
    case 700:
      if (lookahead == 'p') ADVANCE(1201);
      END_STATE();
    case 701:
      if (lookahead == 'p') ADVANCE(1166);
      END_STATE();
    case 702:
      if (lookahead == 'p') ADVANCE(1168);
      END_STATE();
    case 703:
      if (lookahead == 'p') ADVANCE(1160);
      END_STATE();
    case 704:
      if (lookahead == 'p') ADVANCE(1123);
      END_STATE();
    case 705:
      if (lookahead == 'p') ADVANCE(1165);
      END_STATE();
    case 706:
      if (lookahead == 'p') ADVANCE(1167);
      END_STATE();
    case 707:
      if (lookahead == 'p') ADVANCE(1159);
      END_STATE();
    case 708:
      if (lookahead == 'p') ADVANCE(6);
      END_STATE();
    case 709:
      if (lookahead == 'p') ADVANCE(566);
      END_STATE();
    case 710:
      if (lookahead == 'p') ADVANCE(9);
      END_STATE();
    case 711:
      if (lookahead == 'p') ADVANCE(48);
      END_STATE();
    case 712:
      if (lookahead == 'p') ADVANCE(63);
      END_STATE();
    case 713:
      if (lookahead == 'p') ADVANCE(321);
      END_STATE();
    case 714:
      if (lookahead == 'p') ADVANCE(901);
      END_STATE();
    case 715:
      if (lookahead == 'p') ADVANCE(521);
      END_STATE();
    case 716:
      if (lookahead == 'p') ADVANCE(767);
      END_STATE();
    case 717:
      if (lookahead == 'p') ADVANCE(282);
      END_STATE();
    case 718:
      if (lookahead == 'p') ADVANCE(15);
      END_STATE();
    case 719:
      if (lookahead == 'p') ADVANCE(22);
      END_STATE();
    case 720:
      if (lookahead == 'p') ADVANCE(285);
      END_STATE();
    case 721:
      if (lookahead == 'p') ADVANCE(779);
      END_STATE();
    case 722:
      if (lookahead == 'p') ADVANCE(378);
      END_STATE();
    case 723:
      if (lookahead == 'p') ADVANCE(297);
      END_STATE();
    case 724:
      if (lookahead == 'p') ADVANCE(316);
      END_STATE();
    case 725:
      if (lookahead == 'p') ADVANCE(645);
      END_STATE();
    case 726:
      if (lookahead == 'p') ADVANCE(140);
      END_STATE();
    case 727:
      if (lookahead == 'p') ADVANCE(665);
      END_STATE();
    case 728:
      if (lookahead == 'p') ADVANCE(943);
      END_STATE();
    case 729:
      if (lookahead == 'p') ADVANCE(670);
      END_STATE();
    case 730:
      if (lookahead == 'p') ADVANCE(674);
      END_STATE();
    case 731:
      if (lookahead == 'p') ADVANCE(679);
      END_STATE();
    case 732:
      if (lookahead == 'p') ADVANCE(663);
      END_STATE();
    case 733:
      if (lookahead == 'p') ADVANCE(869);
      END_STATE();
    case 734:
      if (lookahead == 'p') ADVANCE(695);
      END_STATE();
    case 735:
      if (lookahead == 'p') ADVANCE(696);
      END_STATE();
    case 736:
      if (lookahead == 'p') ADVANCE(51);
      END_STATE();
    case 737:
      if (lookahead == 'q') ADVANCE(1038);
      END_STATE();
    case 738:
      if (lookahead == 'q') ADVANCE(522);
      END_STATE();
    case 739:
      if (lookahead == 'q') ADVANCE(981);
      END_STATE();
    case 740:
      if (lookahead == 'r') ADVANCE(1033);
      END_STATE();
    case 741:
      if (lookahead == 'r') ADVANCE(1031);
      END_STATE();
    case 742:
      if (lookahead == 'r') ADVANCE(1059);
      END_STATE();
    case 743:
      if (lookahead == 'r') ADVANCE(1063);
      END_STATE();
    case 744:
      if (lookahead == 'r') ADVANCE(1086);
      END_STATE();
    case 745:
      if (lookahead == 'r') ADVANCE(1127);
      END_STATE();
    case 746:
      if (lookahead == 'r') ADVANCE(1203);
      END_STATE();
    case 747:
      if (lookahead == 'r') ADVANCE(1136);
      END_STATE();
    case 748:
      if (lookahead == 'r') ADVANCE(509);
      END_STATE();
    case 749:
      if (lookahead == 'r') ADVANCE(184);
      END_STATE();
    case 750:
      if (lookahead == 'r') ADVANCE(220);
      END_STATE();
    case 751:
      if (lookahead == 'r') ADVANCE(990);
      END_STATE();
    case 752:
      if (lookahead == 'r') ADVANCE(462);
      END_STATE();
    case 753:
      if (lookahead == 'r') ADVANCE(426);
      END_STATE();
    case 754:
      if (lookahead == 'r') ADVANCE(952);
      END_STATE();
    case 755:
      if (lookahead == 'r') ADVANCE(1006);
      END_STATE();
    case 756:
      if (lookahead == 'r') ADVANCE(1007);
      END_STATE();
    case 757:
      if (lookahead == 'r') ADVANCE(537);
      END_STATE();
    case 758:
      if (lookahead == 'r') ADVANCE(74);
      END_STATE();
    case 759:
      if (lookahead == 'r') ADVANCE(1008);
      END_STATE();
    case 760:
      if (lookahead == 'r') ADVANCE(44);
      END_STATE();
    case 761:
      if (lookahead == 'r') ADVANCE(1009);
      END_STATE();
    case 762:
      if (lookahead == 'r') ADVANCE(456);
      END_STATE();
    case 763:
      if (lookahead == 'r') ADVANCE(1010);
      END_STATE();
    case 764:
      if (lookahead == 'r') ADVANCE(96);
      END_STATE();
    case 765:
      if (lookahead == 'r') ADVANCE(1011);
      END_STATE();
    case 766:
      if (lookahead == 'r') ADVANCE(385);
      END_STATE();
    case 767:
      if (lookahead == 'r') ADVANCE(629);
      END_STATE();
    case 768:
      if (lookahead == 'r') ADVANCE(647);
      END_STATE();
    case 769:
      if (lookahead == 'r') ADVANCE(458);
      END_STATE();
    case 770:
      if (lookahead == 'r') ADVANCE(339);
      END_STATE();
    case 771:
      if (lookahead == 'r') ADVANCE(459);
      END_STATE();
    case 772:
      if (lookahead == 'r') ADVANCE(65);
      END_STATE();
    case 773:
      if (lookahead == 'r') ADVANCE(677);
      END_STATE();
    case 774:
      if (lookahead == 'r') ADVANCE(460);
      END_STATE();
    case 775:
      if (lookahead == 'r') ADVANCE(875);
      END_STATE();
    case 776:
      if (lookahead == 'r') ADVANCE(200);
      END_STATE();
    case 777:
      if (lookahead == 'r') ADVANCE(100);
      END_STATE();
    case 778:
      if (lookahead == 'r') ADVANCE(821);
      END_STATE();
    case 779:
      if (lookahead == 'r') ADVANCE(638);
      END_STATE();
    case 780:
      if (lookahead == 'r') ADVANCE(823);
      END_STATE();
    case 781:
      if (lookahead == 'r') ADVANCE(887);
      END_STATE();
    case 782:
      if (lookahead == 'r') ADVANCE(279);
      END_STATE();
    case 783:
      if (lookahead == 'r') ADVANCE(888);
      END_STATE();
    case 784:
      if (lookahead == 'r') ADVANCE(889);
      END_STATE();
    case 785:
      if (lookahead == 'r') ADVANCE(890);
      END_STATE();
    case 786:
      if (lookahead == 'r') ADVANCE(806);
      END_STATE();
    case 787:
      if (lookahead == 'r') ADVANCE(286);
      END_STATE();
    case 788:
      if (lookahead == 'r') ADVANCE(288);
      END_STATE();
    case 789:
      if (lookahead == 'r') ADVANCE(837);
      END_STATE();
    case 790:
      if (lookahead == 'r') ADVANCE(895);
      END_STATE();
    case 791:
      if (lookahead == 'r') ADVANCE(290);
      END_STATE();
    case 792:
      if (lookahead == 'r') ADVANCE(327);
      END_STATE();
    case 793:
      if (lookahead == 'r') ADVANCE(929);
      END_STATE();
    case 794:
      if (lookahead == 'r') ADVANCE(300);
      END_STATE();
    case 795:
      if (lookahead == 'r') ADVANCE(315);
      if (lookahead == 'v') ADVANCE(401);
      END_STATE();
    case 796:
      if (lookahead == 'r') ADVANCE(358);
      END_STATE();
    case 797:
      if (lookahead == 'r') ADVANCE(433);
      END_STATE();
    case 798:
      if (lookahead == 'r') ADVANCE(966);
      END_STATE();
    case 799:
      if (lookahead == 'r') ADVANCE(467);
      END_STATE();
    case 800:
      if (lookahead == 'r') ADVANCE(202);
      if (lookahead == 's') ADVANCE(738);
      if (lookahead == 'x') ADVANCE(849);
      END_STATE();
    case 801:
      if (lookahead == 'r') ADVANCE(434);
      END_STATE();
    case 802:
      if (lookahead == 'r') ADVANCE(262);
      END_STATE();
    case 803:
      if (lookahead == 'r') ADVANCE(205);
      END_STATE();
    case 804:
      if (lookahead == 'r') ADVANCE(477);
      END_STATE();
    case 805:
      if (lookahead == 'r') ADVANCE(349);
      END_STATE();
    case 806:
      if (lookahead == 'r') ADVANCE(657);
      END_STATE();
    case 807:
      if (lookahead == 'r') ADVANCE(145);
      END_STATE();
    case 808:
      if (lookahead == 'r') ADVANCE(997);
      END_STATE();
    case 809:
      if (lookahead == 'r') ADVANCE(498);
      END_STATE();
    case 810:
      if (lookahead == 'r') ADVANCE(732);
      END_STATE();
    case 811:
      if (lookahead == 'r') ADVANCE(222);
      END_STATE();
    case 812:
      if (lookahead == 'r') ADVANCE(985);
      END_STATE();
    case 813:
      if (lookahead == 'r') ADVANCE(501);
      END_STATE();
    case 814:
      if (lookahead == 's') ADVANCE(1086);
      END_STATE();
    case 815:
      if (lookahead == 's') ADVANCE(1052);
      END_STATE();
    case 816:
      if (lookahead == 's') ADVANCE(1051);
      END_STATE();
    case 817:
      if (lookahead == 's') ADVANCE(1114);
      END_STATE();
    case 818:
      if (lookahead == 's') ADVANCE(1061);
      END_STATE();
    case 819:
      if (lookahead == 's') ADVANCE(1106);
      END_STATE();
    case 820:
      if (lookahead == 's') ADVANCE(1173);
      END_STATE();
    case 821:
      if (lookahead == 's') ADVANCE(1176);
      END_STATE();
    case 822:
      if (lookahead == 's') ADVANCE(1174);
      END_STATE();
    case 823:
      if (lookahead == 's') ADVANCE(1179);
      END_STATE();
    case 824:
      if (lookahead == 's') ADVANCE(1175);
      END_STATE();
    case 825:
      if (lookahead == 's') ADVANCE(1184);
      END_STATE();
    case 826:
      if (lookahead == 's') ADVANCE(1185);
      END_STATE();
    case 827:
      if (lookahead == 's') ADVANCE(1180);
      END_STATE();
    case 828:
      if (lookahead == 's') ADVANCE(1189);
      END_STATE();
    case 829:
      if (lookahead == 's') ADVANCE(1187);
      END_STATE();
    case 830:
      if (lookahead == 's') ADVANCE(1181);
      END_STATE();
    case 831:
      if (lookahead == 's') ADVANCE(1190);
      END_STATE();
    case 832:
      if (lookahead == 's') ADVANCE(1188);
      END_STATE();
    case 833:
      if (lookahead == 's') ADVANCE(1191);
      END_STATE();
    case 834:
      if (lookahead == 's') ADVANCE(1186);
      END_STATE();
    case 835:
      if (lookahead == 's') ADVANCE(1182);
      END_STATE();
    case 836:
      if (lookahead == 's') ADVANCE(1183);
      END_STATE();
    case 837:
      if (lookahead == 's') ADVANCE(1177);
      END_STATE();
    case 838:
      if (lookahead == 's') ADVANCE(69);
      END_STATE();
    case 839:
      if (lookahead == 's') ADVANCE(278);
      END_STATE();
    case 840:
      if (lookahead == 's') ADVANCE(443);
      END_STATE();
    case 841:
      if (lookahead == 's') ADVANCE(73);
      END_STATE();
    case 842:
      if (lookahead == 's') ADVANCE(211);
      END_STATE();
    case 843:
      if (lookahead == 's') ADVANCE(914);
      END_STATE();
    case 844:
      if (lookahead == 's') ADVANCE(884);
      END_STATE();
    case 845:
      if (lookahead == 's') ADVANCE(725);
      END_STATE();
    case 846:
      if (lookahead == 's') ADVANCE(446);
      END_STATE();
    case 847:
      if (lookahead == 's') ADVANCE(913);
      END_STATE();
    case 848:
      if (lookahead == 's') ADVANCE(89);
      END_STATE();
    case 849:
      if (lookahead == 's') ADVANCE(819);
      END_STATE();
    case 850:
      if (lookahead == 's') ADVANCE(885);
      END_STATE();
    case 851:
      if (lookahead == 's') ADVANCE(581);
      END_STATE();
    case 852:
      if (lookahead == 's') ADVANCE(678);
      END_STATE();
    case 853:
      if (lookahead == 's') ADVANCE(941);
      END_STATE();
    case 854:
      if (lookahead == 's') ADVANCE(328);
      END_STATE();
    case 855:
      if (lookahead == 's') ADVANCE(916);
      END_STATE();
    case 856:
      if (lookahead == 's') ADVANCE(372);
      END_STATE();
    case 857:
      if (lookahead == 's') ADVANCE(920);
      END_STATE();
    case 858:
      if (lookahead == 's') ADVANCE(332);
      END_STATE();
    case 859:
      if (lookahead == 's') ADVANCE(919);
      END_STATE();
    case 860:
      if (lookahead == 's') ADVANCE(928);
      END_STATE();
    case 861:
      if (lookahead == 's') ADVANCE(930);
      END_STATE();
    case 862:
      if (lookahead == 's') ADVANCE(344);
      END_STATE();
    case 863:
      if (lookahead == 's') ADVANCE(346);
      END_STATE();
    case 864:
      if (lookahead == 's') ADVANCE(356);
      END_STATE();
    case 865:
      if (lookahead == 's') ADVANCE(918);
      END_STATE();
    case 866:
      if (lookahead == 's') ADVANCE(649);
      END_STATE();
    case 867:
      if (lookahead == 's') ADVANCE(367);
      END_STATE();
    case 868:
      if (lookahead == 's') ADVANCE(331);
      END_STATE();
    case 869:
      if (lookahead == 's') ADVANCE(945);
      END_STATE();
    case 870:
      if (lookahead == 's') ADVANCE(345);
      END_STATE();
    case 871:
      if (lookahead == 's') ADVANCE(863);
      END_STATE();
    case 872:
      if (lookahead == 's') ADVANCE(92);
      END_STATE();
    case 873:
      if (lookahead == 's') ADVANCE(212);
      END_STATE();
    case 874:
      if (lookahead == 's') ADVANCE(949);
      END_STATE();
    case 875:
      if (lookahead == 's') ADVANCE(491);
      END_STATE();
    case 876:
      if (lookahead == 's') ADVANCE(493);
      END_STATE();
    case 877:
      if (lookahead == 's') ADVANCE(497);
      END_STATE();
    case 878:
      if (lookahead == 's') ADVANCE(947);
      END_STATE();
    case 879:
      if (lookahead == 's') ADVANCE(697);
      END_STATE();
    case 880:
      if (lookahead == 's') ADVANCE(698);
      END_STATE();
    case 881:
      if (lookahead == 't') ADVANCE(183);
      END_STATE();
    case 882:
      if (lookahead == 't') ADVANCE(1091);
      END_STATE();
    case 883:
      if (lookahead == 't') ADVANCE(1054);
      END_STATE();
    case 884:
      if (lookahead == 't') ADVANCE(1124);
      END_STATE();
    case 885:
      if (lookahead == 't') ADVANCE(1126);
      END_STATE();
    case 886:
      if (lookahead == 't') ADVANCE(1137);
      END_STATE();
    case 887:
      if (lookahead == 't') ADVANCE(1116);
      END_STATE();
    case 888:
      if (lookahead == 't') ADVANCE(1115);
      END_STATE();
    case 889:
      if (lookahead == 't') ADVANCE(1117);
      END_STATE();
    case 890:
      if (lookahead == 't') ADVANCE(1118);
      END_STATE();
    case 891:
      if (lookahead == 't') ADVANCE(1198);
      END_STATE();
    case 892:
      if (lookahead == 't') ADVANCE(1134);
      END_STATE();
    case 893:
      if (lookahead == 't') ADVANCE(1207);
      END_STATE();
    case 894:
      if (lookahead == 't') ADVANCE(1145);
      END_STATE();
    case 895:
      if (lookahead == 't') ADVANCE(1102);
      END_STATE();
    case 896:
      if (lookahead == 't') ADVANCE(1194);
      END_STATE();
    case 897:
      if (lookahead == 't') ADVANCE(902);
      END_STATE();
    case 898:
      if (lookahead == 't') ADVANCE(441);
      END_STATE();
    case 899:
      if (lookahead == 't') ADVANCE(442);
      END_STATE();
    case 900:
      if (lookahead == 't') ADVANCE(1005);
      END_STATE();
    case 901:
      if (lookahead == 't') ADVANCE(36);
      END_STATE();
    case 902:
      if (lookahead == 't') ADVANCE(708);
      END_STATE();
    case 903:
      if (lookahead == 't') ADVANCE(68);
      END_STATE();
    case 904:
      if (lookahead == 't') ADVANCE(514);
      END_STATE();
    case 905:
      if (lookahead == 't') ADVANCE(450);
      END_STATE();
    case 906:
      if (lookahead == 't') ADVANCE(193);
      END_STATE();
    case 907:
      if (lookahead == 't') ADVANCE(451);
      END_STATE();
    case 908:
      if (lookahead == 't') ADVANCE(589);
      END_STATE();
    case 909:
      if (lookahead == 't') ADVANCE(444);
      END_STATE();
    case 910:
      if (lookahead == 't') ADVANCE(28);
      END_STATE();
    case 911:
      if (lookahead == 't') ADVANCE(445);
      END_STATE();
    case 912:
      if (lookahead == 't') ADVANCE(128);
      END_STATE();
    case 913:
      if (lookahead == 't') ADVANCE(583);
      END_STATE();
    case 914:
      if (lookahead == 't') ADVANCE(799);
      END_STATE();
    case 915:
      if (lookahead == 't') ADVANCE(112);
      END_STATE();
    case 916:
      if (lookahead == 't') ADVANCE(10);
      END_STATE();
    case 917:
      if (lookahead == 't') ADVANCE(711);
      END_STATE();
    case 918:
      if (lookahead == 't') ADVANCE(727);
      END_STATE();
    case 919:
      if (lookahead == 't') ADVANCE(146);
      END_STATE();
    case 920:
      if (lookahead == 't') ADVANCE(12);
      END_STATE();
    case 921:
      if (lookahead == 't') ADVANCE(76);
      END_STATE();
    case 922:
      if (lookahead == 't') ADVANCE(13);
      END_STATE();
    case 923:
      if (lookahead == 't') ADVANCE(470);
      END_STATE();
    case 924:
      if (lookahead == 't') ADVANCE(768);
      END_STATE();
    case 925:
      if (lookahead == 't') ADVANCE(77);
      END_STATE();
    case 926:
      if (lookahead == 't') ADVANCE(755);
      END_STATE();
    case 927:
      if (lookahead == 't') ADVANCE(756);
      END_STATE();
    case 928:
      if (lookahead == 't') ADVANCE(45);
      END_STATE();
    case 929:
      if (lookahead == 't') ADVANCE(67);
      END_STATE();
    case 930:
      if (lookahead == 't') ADVANCE(23);
      END_STATE();
    case 931:
      if (lookahead == 't') ADVANCE(27);
      END_STATE();
    case 932:
      if (lookahead == 't') ADVANCE(759);
      END_STATE();
    case 933:
      if (lookahead == 't') ADVANCE(330);
      END_STATE();
    case 934:
      if (lookahead == 't') ADVANCE(319);
      END_STATE();
    case 935:
      if (lookahead == 't') ADVANCE(334);
      END_STATE();
    case 936:
      if (lookahead == 't') ADVANCE(333);
      END_STATE();
    case 937:
      if (lookahead == 't') ADVANCE(379);
      END_STATE();
    case 938:
      if (lookahead == 't') ADVANCE(338);
      END_STATE();
    case 939:
      if (lookahead == 't') ADVANCE(917);
      END_STATE();
    case 940:
      if (lookahead == 't') ADVANCE(402);
      END_STATE();
    case 941:
      if (lookahead == 't') ADVANCE(129);
      END_STATE();
    case 942:
      if (lookahead == 't') ADVANCE(97);
      END_STATE();
    case 943:
      if (lookahead == 't') ADVANCE(386);
      END_STATE();
    case 944:
      if (lookahead == 't') ADVANCE(487);
      END_STATE();
    case 945:
      if (lookahead == 't') ADVANCE(792);
      END_STATE();
    case 946:
      if (lookahead == 't') ADVANCE(1019);
      END_STATE();
    case 947:
      if (lookahead == 't') ADVANCE(804);
      END_STATE();
    case 948:
      if (lookahead == 't') ADVANCE(1020);
      END_STATE();
    case 949:
      if (lookahead == 't') ADVANCE(730);
      END_STATE();
    case 950:
      if (lookahead == 't') ADVANCE(494);
      END_STATE();
    case 951:
      if (lookahead == 't') ADVANCE(496);
      END_STATE();
    case 952:
      if (lookahead == 't') ADVANCE(872);
      END_STATE();
    case 953:
      if (lookahead == 't') ADVANCE(736);
      END_STATE();
    case 954:
      if (lookahead == 't') ADVANCE(408);
      END_STATE();
    case 955:
      if (lookahead == 't') ADVANCE(953);
      END_STATE();
    case 956:
      if (lookahead == 't') ADVANCE(106);
      END_STATE();
    case 957:
      if (lookahead == 'u') ADVANCE(277);
      END_STATE();
    case 958:
      if (lookahead == 'u') ADVANCE(176);
      END_STATE();
    case 959:
      if (lookahead == 'u') ADVANCE(536);
      END_STATE();
    case 960:
      if (lookahead == 'u') ADVANCE(712);
      END_STATE();
    case 961:
      if (lookahead == 'u') ADVANCE(525);
      END_STATE();
    case 962:
      if (lookahead == 'u') ADVANCE(840);
      END_STATE();
    case 963:
      if (lookahead == 'u') ADVANCE(605);
      END_STATE();
    case 964:
      if (lookahead == 'u') ADVANCE(733);
      END_STATE();
    case 965:
      if (lookahead == 'u') ADVANCE(393);
      END_STATE();
    case 966:
      if (lookahead == 'u') ADVANCE(611);
      END_STATE();
    case 967:
      if (lookahead == 'u') ADVANCE(619);
      END_STATE();
    case 968:
      if (lookahead == 'u') ADVANCE(773);
      END_STATE();
    case 969:
      if (lookahead == 'u') ADVANCE(771);
      END_STATE();
    case 970:
      if (lookahead == 'u') ADVANCE(907);
      END_STATE();
    case 971:
      if (lookahead == 'u') ADVANCE(774);
      END_STATE();
    case 972:
      if (lookahead == 'u') ADVANCE(803);
      END_STATE();
    case 973:
      if (lookahead == 'u') ADVANCE(353);
      END_STATE();
    case 974:
      if (lookahead == 'u') ADVANCE(361);
      END_STATE();
    case 975:
      if (lookahead == 'u') ADVANCE(363);
      END_STATE();
    case 976:
      if (lookahead == 'u') ADVANCE(365);
      END_STATE();
    case 977:
      if (lookahead == 'u') ADVANCE(371);
      END_STATE();
    case 978:
      if (lookahead == 'u') ADVANCE(374);
      END_STATE();
    case 979:
      if (lookahead == 'u') ADVANCE(375);
      END_STATE();
    case 980:
      if (lookahead == 'u') ADVANCE(607);
      END_STATE();
    case 981:
      if (lookahead == 'u') ADVANCE(396);
      END_STATE();
    case 982:
      if (lookahead == 'u') ADVANCE(154);
      END_STATE();
    case 983:
      if (lookahead == 'u') ADVANCE(398);
      END_STATE();
    case 984:
      if (lookahead == 'u') ADVANCE(534);
      END_STATE();
    case 985:
      if (lookahead == 'u') ADVANCE(613);
      END_STATE();
    case 986:
      if (lookahead == 'v') ADVANCE(58);
      END_STATE();
    case 987:
      if (lookahead == 'v') ADVANCE(325);
      END_STATE();
    case 988:
      if (lookahead == 'v') ADVANCE(499);
      END_STATE();
    case 989:
      if (lookahead == 'v') ADVANCE(635);
      END_STATE();
    case 990:
      if (lookahead == 'v') ADVANCE(352);
      END_STATE();
    case 991:
      if (lookahead == 'w') ADVANCE(1169);
      END_STATE();
    case 992:
      if (lookahead == 'w') ADVANCE(26);
      END_STATE();
    case 993:
      if (lookahead == 'w') ADVANCE(469);
      END_STATE();
    case 994:
      if (lookahead == 'w') ADVANCE(746);
      END_STATE();
    case 995:
      if (lookahead == 'w') ADVANCE(153);
      END_STATE();
    case 996:
      if (lookahead == 'w') ADVANCE(475);
      END_STATE();
    case 997:
      if (lookahead == 'w') ADVANCE(136);
      END_STATE();
    case 998:
      if (lookahead == 'x') ADVANCE(82);
      END_STATE();
    case 999:
      if (lookahead == 'x') ADVANCE(1001);
      END_STATE();
    case 1000:
      if (lookahead == 'x') ADVANCE(1012);
      END_STATE();
    case 1001:
      if (lookahead == 'x') ADVANCE(1004);
      END_STATE();
    case 1002:
      if (lookahead == 'x') ADVANCE(479);
      END_STATE();
    case 1003:
      if (lookahead == 'x') ADVANCE(937);
      END_STATE();
    case 1004:
      if (lookahead == 'x') ADVANCE(102);
      END_STATE();
    case 1005:
      if (lookahead == 'y') ADVANCE(1139);
      END_STATE();
    case 1006:
      if (lookahead == 'y') ADVANCE(1163);
      END_STATE();
    case 1007:
      if (lookahead == 'y') ADVANCE(1164);
      END_STATE();
    case 1008:
      if (lookahead == 'y') ADVANCE(1146);
      END_STATE();
    case 1009:
      if (lookahead == 'y') ADVANCE(1133);
      END_STATE();
    case 1010:
      if (lookahead == 'y') ADVANCE(1154);
      END_STATE();
    case 1011:
      if (lookahead == 'y') ADVANCE(1152);
      END_STATE();
    case 1012:
      if (lookahead == 'y') ADVANCE(1196);
      END_STATE();
    case 1013:
      if (lookahead == 'y') ADVANCE(540);
      END_STATE();
    case 1014:
      if (lookahead == 'y') ADVANCE(14);
      END_STATE();
    case 1015:
      if (lookahead == 'y') ADVANCE(933);
      END_STATE();
    case 1016:
      if (lookahead == 'y') ADVANCE(572);
      END_STATE();
    case 1017:
      if (lookahead == 'y') ADVANCE(24);
      END_STATE();
    case 1018:
      if (lookahead == 'y') ADVANCE(717);
      END_STATE();
    case 1019:
      if (lookahead == 'y') ADVANCE(720);
      END_STATE();
    case 1020:
      if (lookahead == 'y') ADVANCE(723);
      END_STATE();
    case 1021:
      if (lookahead == 'z') ADVANCE(299);
      END_STATE();
    case 1022:
      if (lookahead == 'z') ADVANCE(668);
      END_STATE();
    case 1023:
      if (lookahead == 'z') ADVANCE(350);
      END_STATE();
    case 1024:
      if (lookahead == 'z') ADVANCE(676);
      END_STATE();
    case 1025:
      if (lookahead == '|') ADVANCE(1034);
      END_STATE();
    case 1026:
      if (eof) ADVANCE(1027);
      if (lookahead == '!') ADVANCE(1092);
      if (lookahead == '#') ADVANCE(1037);
      if (lookahead == '&') ADVANCE(4);
      if (lookahead == '(') ADVANCE(1055);
      if (lookahead == ')') ADVANCE(1057);
      if (lookahead == '/') ADVANCE(1082);
      if (lookahead == '2') ADVANCE(17);
      if (lookahead == '[') ADVANCE(1094);
      if (lookahead == '^') ADVANCE(62);
      if (lookahead == 'a') ADVANCE(511);
      if (lookahead == 'c') ADVANCE(415);
      if (lookahead == 'e') ADVANCE(561);
      if (lookahead == 'f') ADVANCE(113);
      if (lookahead == 'h') ADVANCE(897);
      if (lookahead == 'i') ADVANCE(182);
      if (lookahead == 'l') ADVANCE(364);
      if (lookahead == 'n') ADVANCE(633);
      if (lookahead == 'o') ADVANCE(740);
      if (lookahead == 'r') ADVANCE(108);
      if (lookahead == 's') ADVANCE(454);
      if (lookahead == 't') ADVANCE(189);
      if (lookahead == 'u') ADVANCE(240);
      if (lookahead == 'x') ADVANCE(628);
      if (lookahead == '|') ADVANCE(1025);
      if (lookahead == '}') ADVANCE(1036);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(19);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1026)
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(20);
      END_STATE();
    case 1027:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 1028:
      ACCEPT_TOKEN(anon_sym_in);
      END_STATE();
    case 1029:
      ACCEPT_TOKEN(anon_sym_AMP_AMP);
      END_STATE();
    case 1030:
      ACCEPT_TOKEN(anon_sym_and);
      END_STATE();
    case 1031:
      ACCEPT_TOKEN(anon_sym_xor);
      END_STATE();
    case 1032:
      ACCEPT_TOKEN(anon_sym_CARET_CARET);
      END_STATE();
    case 1033:
      ACCEPT_TOKEN(anon_sym_or);
      END_STATE();
    case 1034:
      ACCEPT_TOKEN(anon_sym_PIPE_PIPE);
      END_STATE();
    case 1035:
      ACCEPT_TOKEN(anon_sym_LBRACE);
      END_STATE();
    case 1036:
      ACCEPT_TOKEN(anon_sym_RBRACE);
      END_STATE();
    case 1037:
      ACCEPT_TOKEN(sym_comment);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(1037);
      END_STATE();
    case 1038:
      ACCEPT_TOKEN(anon_sym_eq);
      END_STATE();
    case 1039:
      ACCEPT_TOKEN(anon_sym_ne);
      END_STATE();
    case 1040:
      ACCEPT_TOKEN(anon_sym_lt);
      END_STATE();
    case 1041:
      ACCEPT_TOKEN(anon_sym_le);
      END_STATE();
    case 1042:
      ACCEPT_TOKEN(anon_sym_le);
      if (lookahead == 'n') ADVANCE(1066);
      END_STATE();
    case 1043:
      ACCEPT_TOKEN(anon_sym_gt);
      END_STATE();
    case 1044:
      ACCEPT_TOKEN(anon_sym_ge);
      END_STATE();
    case 1045:
      ACCEPT_TOKEN(anon_sym_EQ_EQ);
      END_STATE();
    case 1046:
      ACCEPT_TOKEN(anon_sym_BANG_EQ);
      END_STATE();
    case 1047:
      ACCEPT_TOKEN(anon_sym_LT);
      if (lookahead == '=') ADVANCE(1048);
      END_STATE();
    case 1048:
      ACCEPT_TOKEN(anon_sym_LT_EQ);
      END_STATE();
    case 1049:
      ACCEPT_TOKEN(anon_sym_GT);
      if (lookahead == '=') ADVANCE(1050);
      END_STATE();
    case 1050:
      ACCEPT_TOKEN(anon_sym_GT_EQ);
      END_STATE();
    case 1051:
      ACCEPT_TOKEN(anon_sym_contains);
      END_STATE();
    case 1052:
      ACCEPT_TOKEN(anon_sym_matches);
      END_STATE();
    case 1053:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 1054:
      ACCEPT_TOKEN(anon_sym_concat);
      END_STATE();
    case 1055:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 1056:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 1057:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 1058:
      ACCEPT_TOKEN(anon_sym_lookup_json_string);
      END_STATE();
    case 1059:
      ACCEPT_TOKEN(anon_sym_lower);
      END_STATE();
    case 1060:
      ACCEPT_TOKEN(anon_sym_regex_replace);
      END_STATE();
    case 1061:
      ACCEPT_TOKEN(anon_sym_remove_bytes);
      END_STATE();
    case 1062:
      ACCEPT_TOKEN(anon_sym_to_string);
      END_STATE();
    case 1063:
      ACCEPT_TOKEN(anon_sym_upper);
      END_STATE();
    case 1064:
      ACCEPT_TOKEN(anon_sym_url_decode);
      END_STATE();
    case 1065:
      ACCEPT_TOKEN(anon_sym_uuidv4);
      END_STATE();
    case 1066:
      ACCEPT_TOKEN(anon_sym_len);
      END_STATE();
    case 1067:
      ACCEPT_TOKEN(anon_sym_ends_with);
      END_STATE();
    case 1068:
      ACCEPT_TOKEN(anon_sym_starts_with);
      END_STATE();
    case 1069:
      ACCEPT_TOKEN(anon_sym_any);
      END_STATE();
    case 1070:
      ACCEPT_TOKEN(anon_sym_all);
      END_STATE();
    case 1071:
      ACCEPT_TOKEN(anon_sym_LBRACK_STAR_RBRACK);
      END_STATE();
    case 1072:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(1073);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(1073);
      END_STATE();
    case 1073:
      ACCEPT_TOKEN(sym_number);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1073);
      END_STATE();
    case 1074:
      ACCEPT_TOKEN(sym_string);
      END_STATE();
    case 1075:
      ACCEPT_TOKEN(anon_sym_true);
      END_STATE();
    case 1076:
      ACCEPT_TOKEN(anon_sym_false);
      END_STATE();
    case 1077:
      ACCEPT_TOKEN(sym_ipv4);
      END_STATE();
    case 1078:
      ACCEPT_TOKEN(sym_ipv4);
      if (lookahead == '5') ADVANCE(1079);
      if (('6' <= lookahead && lookahead <= '9')) ADVANCE(1077);
      if (('0' <= lookahead && lookahead <= '4')) ADVANCE(1080);
      END_STATE();
    case 1079:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '5')) ADVANCE(1077);
      END_STATE();
    case 1080:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1077);
      END_STATE();
    case 1081:
      ACCEPT_TOKEN(sym_ipv4);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1080);
      END_STATE();
    case 1082:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 1083:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      END_STATE();
    case 1084:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(1083);
      END_STATE();
    case 1085:
      ACCEPT_TOKEN(aux_sym_ip_range_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(1083);
      END_STATE();
    case 1086:
      ACCEPT_TOKEN(sym_ip_list);
      END_STATE();
    case 1087:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == '.') ADVANCE(114);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1090);
      END_STATE();
    case 1088:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'c') ADVANCE(1089);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1090);
      END_STATE();
    case 1089:
      ACCEPT_TOKEN(sym_ip_list);
      if (lookahead == 'f') ADVANCE(1087);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1090);
      END_STATE();
    case 1090:
      ACCEPT_TOKEN(sym_ip_list);
      if (('0' <= lookahead && lookahead <= '9') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(1090);
      END_STATE();
    case 1091:
      ACCEPT_TOKEN(anon_sym_not);
      END_STATE();
    case 1092:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 1093:
      ACCEPT_TOKEN(anon_sym_BANG);
      if (lookahead == '=') ADVANCE(1046);
      END_STATE();
    case 1094:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 1095:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      if (lookahead == '*') ADVANCE(61);
      END_STATE();
    case 1096:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 1097:
      ACCEPT_TOKEN(anon_sym_STAR);
      END_STATE();
    case 1098:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTsec);
      END_STATE();
    case 1099:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec);
      END_STATE();
    case 1100:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTasnum);
      END_STATE();
    case 1101:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTscore);
      END_STATE();
    case 1102:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_port);
      END_STATE();
    case 1103:
      ACCEPT_TOKEN(anon_sym_cf_DOTthreat_score);
      END_STATE();
    case 1104:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore);
      if (lookahead == '.') ADVANCE(800);
      END_STATE();
    case 1105:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTsqli);
      END_STATE();
    case 1106:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTxss);
      END_STATE();
    case 1107:
      ACCEPT_TOKEN(anon_sym_cf_DOTwaf_DOTscore_DOTrce);
      END_STATE();
    case 1108:
      ACCEPT_TOKEN(anon_sym_icmp_DOTtype);
      END_STATE();
    case 1109:
      ACCEPT_TOKEN(anon_sym_icmp_DOTcode);
      END_STATE();
    case 1110:
      ACCEPT_TOKEN(anon_sym_ip_DOThdr_len);
      END_STATE();
    case 1111:
      ACCEPT_TOKEN(anon_sym_ip_DOTlen);
      END_STATE();
    case 1112:
      ACCEPT_TOKEN(anon_sym_ip_DOTopt_DOTtype);
      END_STATE();
    case 1113:
      ACCEPT_TOKEN(anon_sym_ip_DOTttl);
      END_STATE();
    case 1114:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags);
      if (lookahead == '.') ADVANCE(127);
      END_STATE();
    case 1115:
      ACCEPT_TOKEN(anon_sym_tcp_DOTsrcport);
      END_STATE();
    case 1116:
      ACCEPT_TOKEN(anon_sym_tcp_DOTdstport);
      END_STATE();
    case 1117:
      ACCEPT_TOKEN(anon_sym_udp_DOTdstport);
      END_STATE();
    case 1118:
      ACCEPT_TOKEN(anon_sym_udp_DOTsrcport);
      END_STATE();
    case 1119:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTsize);
      END_STATE();
    case 1120:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTcode);
      END_STATE();
    case 1121:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOT1xxx_code);
      END_STATE();
    case 1122:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc);
      if (lookahead == '.') ADVANCE(186);
      END_STATE();
    case 1123:
      ACCEPT_TOKEN(anon_sym_cf_DOTedge_DOTserver_ip);
      END_STATE();
    case 1124:
      ACCEPT_TOKEN(anon_sym_ip_DOTdst);
      if (lookahead == '.') ADVANCE(196);
      END_STATE();
    case 1125:
      ACCEPT_TOKEN(anon_sym_http_DOTcookie);
      END_STATE();
    case 1126:
      ACCEPT_TOKEN(anon_sym_http_DOThost);
      END_STATE();
    case 1127:
      ACCEPT_TOKEN(anon_sym_http_DOTreferer);
      END_STATE();
    case 1128:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTfull_uri);
      END_STATE();
    case 1129:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTmethod);
      END_STATE();
    case 1130:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(139);
      END_STATE();
    case 1131:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath);
      if (lookahead == '.') ADVANCE(314);
      END_STATE();
    case 1132:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension);
      END_STATE();
    case 1133:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 1134:
      ACCEPT_TOKEN(anon_sym_http_DOTuser_agent);
      END_STATE();
    case 1135:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTversion);
      END_STATE();
    case 1136:
      ACCEPT_TOKEN(anon_sym_http_DOTx_forwarded_for);
      END_STATE();
    case 1137:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlat);
      END_STATE();
    case 1138:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTlon);
      END_STATE();
    case 1139:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcity);
      END_STATE();
    case 1140:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTpostal_code);
      END_STATE();
    case 1141:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTmetro_code);
      END_STATE();
    case 1142:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTregion);
      if (lookahead == '_') ADVANCE(224);
      END_STATE();
    case 1143:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTregion_code);
      END_STATE();
    case 1144:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTtimezone_DOTname);
      END_STATE();
    case 1145:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcontinent);
      END_STATE();
    case 1146:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTcountry);
      END_STATE();
    case 1147:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code);
      END_STATE();
    case 1148:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code);
      END_STATE();
    case 1149:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri);
      END_STATE();
    case 1150:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri);
      if (lookahead == '.') ADVANCE(166);
      END_STATE();
    case 1151:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath);
      END_STATE();
    case 1152:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery);
      END_STATE();
    case 1153:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTja3_hash);
      END_STATE();
    case 1154:
      ACCEPT_TOKEN(anon_sym_cf_DOTverified_bot_category);
      END_STATE();
    case 1155:
      ACCEPT_TOKEN(anon_sym_cf_DOThostname_DOTmetadata);
      END_STATE();
    case 1156:
      ACCEPT_TOKEN(anon_sym_cf_DOTworker_DOTupstream_zone);
      END_STATE();
    case 1157:
      ACCEPT_TOKEN(anon_sym_cf_DOTcolo_DOTname);
      END_STATE();
    case 1158:
      ACCEPT_TOKEN(anon_sym_cf_DOTcolo_DOTregion);
      END_STATE();
    case 1159:
      ACCEPT_TOKEN(anon_sym_icmp);
      END_STATE();
    case 1160:
      ACCEPT_TOKEN(anon_sym_icmp);
      if (lookahead == '.') ADVANCE(194);
      END_STATE();
    case 1161:
      ACCEPT_TOKEN(anon_sym_ip);
      if (lookahead == '.') ADVANCE(259);
      END_STATE();
    case 1162:
      ACCEPT_TOKEN(anon_sym_ip);
      if (lookahead == '.') ADVANCE(264);
      END_STATE();
    case 1163:
      ACCEPT_TOKEN(anon_sym_ip_DOTdst_DOTcountry);
      END_STATE();
    case 1164:
      ACCEPT_TOKEN(anon_sym_ip_DOTsrc_DOTcountry);
      END_STATE();
    case 1165:
      ACCEPT_TOKEN(anon_sym_tcp);
      END_STATE();
    case 1166:
      ACCEPT_TOKEN(anon_sym_tcp);
      if (lookahead == '.') ADVANCE(241);
      END_STATE();
    case 1167:
      ACCEPT_TOKEN(anon_sym_udp);
      END_STATE();
    case 1168:
      ACCEPT_TOKEN(anon_sym_udp);
      if (lookahead == '.') ADVANCE(269);
      END_STATE();
    case 1169:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTraw);
      END_STATE();
    case 1170:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTmime);
      END_STATE();
    case 1171:
      ACCEPT_TOKEN(anon_sym_cf_DOTresponse_DOTerror_type);
      END_STATE();
    case 1172:
      ACCEPT_TOKEN(anon_sym_cf_DOTrandom_seed);
      END_STATE();
    case 1173:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTcookies);
      END_STATE();
    case 1174:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTargs);
      if (lookahead == '.') ADVANCE(617);
      END_STATE();
    case 1175:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs);
      if (lookahead == '.') ADVANCE(621);
      END_STATE();
    case 1176:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(614);
      END_STATE();
    case 1177:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders);
      if (lookahead == '.') ADVANCE(615);
      END_STATE();
    case 1178:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTform);
      if (lookahead == '.') ADVANCE(620);
      END_STATE();
    case 1179:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTheaders);
      if (lookahead == '.') ADVANCE(618);
      END_STATE();
    case 1180:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames);
      END_STATE();
    case 1181:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues);
      END_STATE();
    case 1182:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames);
      END_STATE();
    case 1183:
      ACCEPT_TOKEN(anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues);
      END_STATE();
    case 1184:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTnames);
      END_STATE();
    case 1185:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTvalues);
      END_STATE();
    case 1186:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTaccepted_languages);
      END_STATE();
    case 1187:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames);
      END_STATE();
    case 1188:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues);
      END_STATE();
    case 1189:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTheaders_DOTnames);
      END_STATE();
    case 1190:
      ACCEPT_TOKEN(anon_sym_http_DOTresponse_DOTheaders_DOTvalues);
      END_STATE();
    case 1191:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTdetection_ids);
      END_STATE();
    case 1192:
      ACCEPT_TOKEN(anon_sym_ip_DOTgeoip_DOTis_in_european_union);
      END_STATE();
    case 1193:
      ACCEPT_TOKEN(anon_sym_ssl);
      END_STATE();
    case 1194:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTverified_bot);
      END_STATE();
    case 1195:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed);
      END_STATE();
    case 1196:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTcorporate_proxy);
      END_STATE();
    case 1197:
      ACCEPT_TOKEN(anon_sym_cf_DOTbot_management_DOTstatic_resource);
      END_STATE();
    case 1198:
      ACCEPT_TOKEN(anon_sym_cf_DOTclient_DOTbot);
      END_STATE();
    case 1199:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_revoked);
      END_STATE();
    case 1200:
      ACCEPT_TOKEN(anon_sym_cf_DOTtls_client_auth_DOTcert_verified);
      END_STATE();
    case 1201:
      ACCEPT_TOKEN(anon_sym_sip);
      END_STATE();
    case 1202:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTack);
      END_STATE();
    case 1203:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTcwr);
      END_STATE();
    case 1204:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTecn);
      END_STATE();
    case 1205:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTfin);
      END_STATE();
    case 1206:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTpush);
      END_STATE();
    case 1207:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTreset);
      END_STATE();
    case 1208:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTsyn);
      END_STATE();
    case 1209:
      ACCEPT_TOKEN(anon_sym_tcp_DOTflags_DOTurg);
      END_STATE();
    case 1210:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTheaders_DOTtruncated);
      END_STATE();
    case 1211:
      ACCEPT_TOKEN(anon_sym_http_DOTrequest_DOTbody_DOTtruncated);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 1026},
  [2] = {.lex_state = 1026},
  [3] = {.lex_state = 1026},
  [4] = {.lex_state = 1026},
  [5] = {.lex_state = 1026},
  [6] = {.lex_state = 1026},
  [7] = {.lex_state = 1026},
  [8] = {.lex_state = 1026},
  [9] = {.lex_state = 1026},
  [10] = {.lex_state = 1026},
  [11] = {.lex_state = 1026},
  [12] = {.lex_state = 1026},
  [13] = {.lex_state = 1026},
  [14] = {.lex_state = 1026},
  [15] = {.lex_state = 1026},
  [16] = {.lex_state = 1026},
  [17] = {.lex_state = 1026},
  [18] = {.lex_state = 1026},
  [19] = {.lex_state = 1026},
  [20] = {.lex_state = 1026},
  [21] = {.lex_state = 1026},
  [22] = {.lex_state = 1026},
  [23] = {.lex_state = 1026},
  [24] = {.lex_state = 1026},
  [25] = {.lex_state = 1026},
  [26] = {.lex_state = 1026},
  [27] = {.lex_state = 1026},
  [28] = {.lex_state = 1026},
  [29] = {.lex_state = 1026},
  [30] = {.lex_state = 1026},
  [31] = {.lex_state = 1},
  [32] = {.lex_state = 1},
  [33] = {.lex_state = 1},
  [34] = {.lex_state = 1},
  [35] = {.lex_state = 1},
  [36] = {.lex_state = 1},
  [37] = {.lex_state = 1},
  [38] = {.lex_state = 1},
  [39] = {.lex_state = 1},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
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
  [62] = {.lex_state = 0},
  [63] = {.lex_state = 0},
  [64] = {.lex_state = 1026},
  [65] = {.lex_state = 1026},
  [66] = {.lex_state = 1026},
  [67] = {.lex_state = 0},
  [68] = {.lex_state = 0},
  [69] = {.lex_state = 0},
  [70] = {.lex_state = 0},
  [71] = {.lex_state = 0},
  [72] = {.lex_state = 0},
  [73] = {.lex_state = 0},
  [74] = {.lex_state = 0},
  [75] = {.lex_state = 1},
  [76] = {.lex_state = 1},
  [77] = {.lex_state = 1},
  [78] = {.lex_state = 1},
  [79] = {.lex_state = 1},
  [80] = {.lex_state = 1},
  [81] = {.lex_state = 1},
  [82] = {.lex_state = 1},
  [83] = {.lex_state = 0},
  [84] = {.lex_state = 1026},
  [85] = {.lex_state = 1},
  [86] = {.lex_state = 1026},
  [87] = {.lex_state = 1},
  [88] = {.lex_state = 1026},
  [89] = {.lex_state = 1},
  [90] = {.lex_state = 1},
  [91] = {.lex_state = 1026},
  [92] = {.lex_state = 1},
  [93] = {.lex_state = 1},
  [94] = {.lex_state = 1},
  [95] = {.lex_state = 1},
  [96] = {.lex_state = 1},
  [97] = {.lex_state = 0},
  [98] = {.lex_state = 1},
  [99] = {.lex_state = 1},
  [100] = {.lex_state = 1026},
  [101] = {.lex_state = 0},
  [102] = {.lex_state = 1},
  [103] = {.lex_state = 1},
  [104] = {.lex_state = 1},
  [105] = {.lex_state = 0},
  [106] = {.lex_state = 1},
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
  [128] = {.lex_state = 0},
  [129] = {.lex_state = 0},
  [130] = {.lex_state = 0},
  [131] = {.lex_state = 0},
  [132] = {.lex_state = 0},
  [133] = {.lex_state = 0},
  [134] = {.lex_state = 0},
  [135] = {.lex_state = 0},
  [136] = {.lex_state = 0},
  [137] = {.lex_state = 1026},
  [138] = {.lex_state = 1026},
  [139] = {.lex_state = 0},
  [140] = {.lex_state = 0},
  [141] = {.lex_state = 0},
  [142] = {.lex_state = 0},
  [143] = {.lex_state = 0},
  [144] = {.lex_state = 0},
  [145] = {.lex_state = 1026},
  [146] = {.lex_state = 0},
  [147] = {.lex_state = 0},
  [148] = {.lex_state = 0},
  [149] = {.lex_state = 0},
  [150] = {.lex_state = 3},
  [151] = {.lex_state = 1026},
  [152] = {.lex_state = 0},
  [153] = {.lex_state = 0},
  [154] = {.lex_state = 0},
  [155] = {.lex_state = 0},
  [156] = {.lex_state = 0},
  [157] = {.lex_state = 1026},
  [158] = {.lex_state = 0},
  [159] = {.lex_state = 0},
  [160] = {.lex_state = 0},
  [161] = {.lex_state = 0},
  [162] = {.lex_state = 0},
  [163] = {.lex_state = 0},
  [164] = {.lex_state = 0},
  [165] = {.lex_state = 1026},
  [166] = {.lex_state = 0},
  [167] = {.lex_state = 0},
  [168] = {.lex_state = 0},
  [169] = {.lex_state = 0},
  [170] = {.lex_state = 1},
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
  [184] = {.lex_state = 1026},
  [185] = {.lex_state = 0},
  [186] = {.lex_state = 0},
  [187] = {.lex_state = 0},
  [188] = {.lex_state = 1026},
  [189] = {.lex_state = 0},
  [190] = {.lex_state = 1026},
  [191] = {.lex_state = 0},
  [192] = {.lex_state = 0},
  [193] = {.lex_state = 0},
  [194] = {.lex_state = 0},
  [195] = {.lex_state = 0},
  [196] = {.lex_state = 0},
  [197] = {.lex_state = 1026},
  [198] = {.lex_state = 0},
  [199] = {.lex_state = 1026},
  [200] = {.lex_state = 0},
  [201] = {.lex_state = 0},
  [202] = {.lex_state = 0},
  [203] = {.lex_state = 0},
  [204] = {.lex_state = 1},
  [205] = {.lex_state = 1},
  [206] = {.lex_state = 1},
  [207] = {.lex_state = 1},
  [208] = {.lex_state = 1026},
  [209] = {.lex_state = 1026},
  [210] = {.lex_state = 1026},
  [211] = {.lex_state = 1026},
  [212] = {.lex_state = 1026},
  [213] = {.lex_state = 0},
  [214] = {.lex_state = 0},
  [215] = {.lex_state = 0},
  [216] = {.lex_state = 0},
  [217] = {.lex_state = 1026},
  [218] = {.lex_state = 0},
  [219] = {.lex_state = 0},
  [220] = {.lex_state = 0},
  [221] = {.lex_state = 0},
  [222] = {.lex_state = 0},
  [223] = {.lex_state = 1026},
  [224] = {.lex_state = 1026},
  [225] = {.lex_state = 0},
  [226] = {.lex_state = 1026},
  [227] = {.lex_state = 0},
  [228] = {.lex_state = 0},
  [229] = {.lex_state = 0},
  [230] = {.lex_state = 0},
  [231] = {.lex_state = 0},
  [232] = {.lex_state = 0},
  [233] = {.lex_state = 0},
  [234] = {.lex_state = 0},
  [235] = {.lex_state = 1026},
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
  [247] = {.lex_state = 0},
  [248] = {.lex_state = 0},
  [249] = {.lex_state = 0},
  [250] = {.lex_state = 0},
  [251] = {.lex_state = 0},
  [252] = {.lex_state = 0},
  [253] = {.lex_state = 0},
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
    [anon_sym_icmp_DOTtype] = ACTIONS(1),
    [anon_sym_icmp_DOTcode] = ACTIONS(1),
    [anon_sym_ip_DOThdr_len] = ACTIONS(1),
    [anon_sym_ip_DOTlen] = ACTIONS(1),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(1),
    [anon_sym_ip_DOTttl] = ACTIONS(1),
    [anon_sym_tcp_DOTflags] = ACTIONS(1),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(1),
    [anon_sym_tcp_DOTdstport] = ACTIONS(1),
    [anon_sym_udp_DOTdstport] = ACTIONS(1),
    [anon_sym_udp_DOTsrcport] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(1),
    [anon_sym_ip_DOTsrc] = ACTIONS(1),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(1),
    [anon_sym_ip_DOTdst] = ACTIONS(1),
    [anon_sym_http_DOTcookie] = ACTIONS(1),
    [anon_sym_http_DOThost] = ACTIONS(1),
    [anon_sym_http_DOTreferer] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(1),
    [anon_sym_http_DOTuser_agent] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(1),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(1),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(1),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(1),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(1),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(1),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(1),
    [anon_sym_icmp] = ACTIONS(1),
    [anon_sym_ip] = ACTIONS(1),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(1),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(1),
    [anon_sym_tcp] = ACTIONS(1),
    [anon_sym_udp] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(1),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(1),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(1),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(1),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(1),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(1),
    [anon_sym_ssl] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(1),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(1),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(1),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(1),
    [anon_sym_sip] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(1),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(1),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(1),
  },
  [1] = {
    [sym_source_file] = STATE(219),
    [sym__expression] = STATE(29),
    [sym_not_expression] = STATE(29),
    [sym_in_expression] = STATE(29),
    [sym_compound_expression] = STATE(29),
    [sym_simple_expression] = STATE(29),
    [sym__bool_lhs] = STATE(29),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(29),
    [sym_boolean] = STATE(29),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(29),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
    [sym_bool_field] = STATE(24),
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
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [2] = {
    [sym__expression] = STATE(29),
    [sym_not_expression] = STATE(29),
    [sym_in_expression] = STATE(29),
    [sym_compound_expression] = STATE(29),
    [sym_simple_expression] = STATE(29),
    [sym__bool_lhs] = STATE(29),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(29),
    [sym_boolean] = STATE(29),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(29),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
    [sym_bool_field] = STATE(24),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(55),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(57),
    [anon_sym_LPAREN] = ACTIONS(60),
    [anon_sym_lookup_json_string] = ACTIONS(63),
    [anon_sym_lower] = ACTIONS(66),
    [anon_sym_regex_replace] = ACTIONS(69),
    [anon_sym_remove_bytes] = ACTIONS(72),
    [anon_sym_to_string] = ACTIONS(75),
    [anon_sym_upper] = ACTIONS(66),
    [anon_sym_url_decode] = ACTIONS(66),
    [anon_sym_uuidv4] = ACTIONS(78),
    [anon_sym_len] = ACTIONS(81),
    [anon_sym_ends_with] = ACTIONS(84),
    [anon_sym_starts_with] = ACTIONS(84),
    [anon_sym_any] = ACTIONS(87),
    [anon_sym_all] = ACTIONS(87),
    [anon_sym_true] = ACTIONS(90),
    [anon_sym_false] = ACTIONS(90),
    [anon_sym_not] = ACTIONS(93),
    [anon_sym_BANG] = ACTIONS(93),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(96),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(96),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(96),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(96),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(99),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(96),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(96),
    [anon_sym_icmp_DOTtype] = ACTIONS(96),
    [anon_sym_icmp_DOTcode] = ACTIONS(96),
    [anon_sym_ip_DOThdr_len] = ACTIONS(96),
    [anon_sym_ip_DOTlen] = ACTIONS(96),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(96),
    [anon_sym_ip_DOTttl] = ACTIONS(96),
    [anon_sym_tcp_DOTflags] = ACTIONS(99),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(96),
    [anon_sym_tcp_DOTdstport] = ACTIONS(96),
    [anon_sym_udp_DOTdstport] = ACTIONS(96),
    [anon_sym_udp_DOTsrcport] = ACTIONS(96),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(96),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(96),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(96),
    [anon_sym_ip_DOTsrc] = ACTIONS(102),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(105),
    [anon_sym_ip_DOTdst] = ACTIONS(102),
    [anon_sym_http_DOTcookie] = ACTIONS(108),
    [anon_sym_http_DOThost] = ACTIONS(108),
    [anon_sym_http_DOTreferer] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(111),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(111),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_http_DOTuser_agent] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(108),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(111),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(108),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(111),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(108),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(108),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(108),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(108),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(108),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(108),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(108),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(108),
    [anon_sym_icmp] = ACTIONS(111),
    [anon_sym_ip] = ACTIONS(111),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(108),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(108),
    [anon_sym_tcp] = ACTIONS(111),
    [anon_sym_udp] = ACTIONS(111),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(108),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(108),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(114),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(117),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(117),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(117),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(117),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(117),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(120),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(120),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(120),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(120),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(120),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(123),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(126),
    [anon_sym_ssl] = ACTIONS(126),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(126),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(126),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(126),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(126),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(126),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(126),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(126),
    [anon_sym_sip] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(126),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(126),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(126),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(126),
  },
  [3] = {
    [sym__expression] = STATE(29),
    [sym_not_expression] = STATE(29),
    [sym_in_expression] = STATE(29),
    [sym_compound_expression] = STATE(29),
    [sym_simple_expression] = STATE(29),
    [sym__bool_lhs] = STATE(29),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(29),
    [sym_boolean] = STATE(29),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(29),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
    [sym_bool_field] = STATE(24),
    [aux_sym_source_file_repeat1] = STATE(2),
    [ts_builtin_sym_end] = ACTIONS(129),
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
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [4] = {
    [sym__expression] = STATE(14),
    [sym_not_expression] = STATE(14),
    [sym_in_expression] = STATE(14),
    [sym_compound_expression] = STATE(14),
    [sym_simple_expression] = STATE(14),
    [sym__bool_lhs] = STATE(14),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(14),
    [sym_boolean] = STATE(14),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(14),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
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
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [5] = {
    [sym__expression] = STATE(83),
    [sym_not_expression] = STATE(83),
    [sym_in_expression] = STATE(83),
    [sym_compound_expression] = STATE(83),
    [sym_simple_expression] = STATE(83),
    [sym__bool_lhs] = STATE(83),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(83),
    [sym_boolean] = STATE(83),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(83),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
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
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [6] = {
    [sym__expression] = STATE(11),
    [sym_not_expression] = STATE(11),
    [sym_in_expression] = STATE(11),
    [sym_compound_expression] = STATE(11),
    [sym_simple_expression] = STATE(11),
    [sym__bool_lhs] = STATE(11),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(11),
    [sym_boolean] = STATE(11),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(11),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
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
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [7] = {
    [sym__expression] = STATE(23),
    [sym_not_expression] = STATE(23),
    [sym_in_expression] = STATE(23),
    [sym_compound_expression] = STATE(23),
    [sym_simple_expression] = STATE(23),
    [sym__bool_lhs] = STATE(23),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(23),
    [sym_boolean] = STATE(23),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(23),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
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
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [8] = {
    [sym__expression] = STATE(12),
    [sym_not_expression] = STATE(12),
    [sym_in_expression] = STATE(12),
    [sym_compound_expression] = STATE(12),
    [sym_simple_expression] = STATE(12),
    [sym__bool_lhs] = STATE(12),
    [sym__number_lhs] = STATE(81),
    [sym_string_func] = STATE(33),
    [sym_number_func] = STATE(81),
    [sym_bool_func] = STATE(24),
    [sym_array_func] = STATE(25),
    [sym_group] = STATE(12),
    [sym_boolean] = STATE(12),
    [sym_not_operator] = STATE(4),
    [sym_number_array] = STATE(217),
    [sym_bool_array] = STATE(212),
    [sym_string_array] = STATE(211),
    [sym_boollike_field] = STATE(12),
    [sym_numberlike_field] = STATE(81),
    [sym_stringlike_field] = STATE(76),
    [sym_number_field] = STATE(77),
    [sym_ip_field] = STATE(87),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [sym_array_number_field] = STATE(208),
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
    [anon_sym_any] = ACTIONS(27),
    [anon_sym_all] = ACTIONS(27),
    [anon_sym_true] = ACTIONS(29),
    [anon_sym_false] = ACTIONS(29),
    [anon_sym_not] = ACTIONS(31),
    [anon_sym_BANG] = ACTIONS(31),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(33),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(33),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(33),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(33),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(35),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(33),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(33),
    [anon_sym_icmp_DOTtype] = ACTIONS(33),
    [anon_sym_icmp_DOTcode] = ACTIONS(33),
    [anon_sym_ip_DOThdr_len] = ACTIONS(33),
    [anon_sym_ip_DOTlen] = ACTIONS(33),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(33),
    [anon_sym_ip_DOTttl] = ACTIONS(33),
    [anon_sym_tcp_DOTflags] = ACTIONS(35),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(33),
    [anon_sym_tcp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTdstport] = ACTIONS(33),
    [anon_sym_udp_DOTsrcport] = ACTIONS(33),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(33),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(33),
    [anon_sym_ip_DOTsrc] = ACTIONS(37),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(39),
    [anon_sym_ip_DOTdst] = ACTIONS(37),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(43),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(43),
    [anon_sym_udp] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(51),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(53),
    [anon_sym_ssl] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(53),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(53),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(53),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(53),
    [anon_sym_sip] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(53),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(53),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(53),
  },
  [9] = {
    [ts_builtin_sym_end] = ACTIONS(131),
    [anon_sym_AMP_AMP] = ACTIONS(131),
    [anon_sym_and] = ACTIONS(131),
    [anon_sym_xor] = ACTIONS(131),
    [anon_sym_CARET_CARET] = ACTIONS(131),
    [anon_sym_or] = ACTIONS(131),
    [anon_sym_PIPE_PIPE] = ACTIONS(131),
    [anon_sym_RBRACE] = ACTIONS(131),
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
    [anon_sym_any] = ACTIONS(131),
    [anon_sym_all] = ACTIONS(131),
    [anon_sym_true] = ACTIONS(131),
    [anon_sym_false] = ACTIONS(131),
    [sym_ipv4] = ACTIONS(131),
    [anon_sym_SLASH] = ACTIONS(133),
    [anon_sym_not] = ACTIONS(131),
    [anon_sym_BANG] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(131),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(131),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(135),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(131),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(131),
    [anon_sym_icmp_DOTtype] = ACTIONS(131),
    [anon_sym_icmp_DOTcode] = ACTIONS(131),
    [anon_sym_ip_DOThdr_len] = ACTIONS(131),
    [anon_sym_ip_DOTlen] = ACTIONS(131),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(131),
    [anon_sym_ip_DOTttl] = ACTIONS(131),
    [anon_sym_tcp_DOTflags] = ACTIONS(135),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(131),
    [anon_sym_tcp_DOTdstport] = ACTIONS(131),
    [anon_sym_udp_DOTdstport] = ACTIONS(131),
    [anon_sym_udp_DOTsrcport] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc] = ACTIONS(135),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(131),
    [anon_sym_ip_DOTdst] = ACTIONS(135),
    [anon_sym_http_DOTcookie] = ACTIONS(131),
    [anon_sym_http_DOThost] = ACTIONS(131),
    [anon_sym_http_DOTreferer] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_http_DOTuser_agent] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(131),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(135),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(135),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(131),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(131),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(131),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(131),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(131),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(131),
    [anon_sym_icmp] = ACTIONS(135),
    [anon_sym_ip] = ACTIONS(135),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(131),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(131),
    [anon_sym_tcp] = ACTIONS(135),
    [anon_sym_udp] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(131),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(135),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(135),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(135),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(131),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(131),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(131),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(131),
    [anon_sym_ssl] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(131),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(131),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(131),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(131),
    [anon_sym_sip] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(131),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(131),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(131),
  },
  [10] = {
    [ts_builtin_sym_end] = ACTIONS(137),
    [anon_sym_AMP_AMP] = ACTIONS(137),
    [anon_sym_and] = ACTIONS(137),
    [anon_sym_xor] = ACTIONS(137),
    [anon_sym_CARET_CARET] = ACTIONS(137),
    [anon_sym_or] = ACTIONS(137),
    [anon_sym_PIPE_PIPE] = ACTIONS(137),
    [anon_sym_RBRACE] = ACTIONS(137),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(137),
    [anon_sym_LPAREN] = ACTIONS(137),
    [anon_sym_RPAREN] = ACTIONS(137),
    [anon_sym_lookup_json_string] = ACTIONS(137),
    [anon_sym_lower] = ACTIONS(137),
    [anon_sym_regex_replace] = ACTIONS(137),
    [anon_sym_remove_bytes] = ACTIONS(137),
    [anon_sym_to_string] = ACTIONS(137),
    [anon_sym_upper] = ACTIONS(137),
    [anon_sym_url_decode] = ACTIONS(137),
    [anon_sym_uuidv4] = ACTIONS(137),
    [anon_sym_len] = ACTIONS(137),
    [anon_sym_ends_with] = ACTIONS(137),
    [anon_sym_starts_with] = ACTIONS(137),
    [anon_sym_any] = ACTIONS(137),
    [anon_sym_all] = ACTIONS(137),
    [anon_sym_true] = ACTIONS(137),
    [anon_sym_false] = ACTIONS(137),
    [sym_ipv4] = ACTIONS(137),
    [anon_sym_not] = ACTIONS(137),
    [anon_sym_BANG] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(137),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(137),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(137),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(139),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(137),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(137),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(137),
    [anon_sym_icmp_DOTtype] = ACTIONS(137),
    [anon_sym_icmp_DOTcode] = ACTIONS(137),
    [anon_sym_ip_DOThdr_len] = ACTIONS(137),
    [anon_sym_ip_DOTlen] = ACTIONS(137),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(137),
    [anon_sym_ip_DOTttl] = ACTIONS(137),
    [anon_sym_tcp_DOTflags] = ACTIONS(139),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(137),
    [anon_sym_tcp_DOTdstport] = ACTIONS(137),
    [anon_sym_udp_DOTdstport] = ACTIONS(137),
    [anon_sym_udp_DOTsrcport] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(137),
    [anon_sym_ip_DOTsrc] = ACTIONS(139),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(137),
    [anon_sym_ip_DOTdst] = ACTIONS(139),
    [anon_sym_http_DOTcookie] = ACTIONS(137),
    [anon_sym_http_DOThost] = ACTIONS(137),
    [anon_sym_http_DOTreferer] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(137),
    [anon_sym_http_DOTuser_agent] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(137),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(139),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(139),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(137),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(137),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(137),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(137),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(137),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(137),
    [anon_sym_icmp] = ACTIONS(139),
    [anon_sym_ip] = ACTIONS(139),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(137),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(137),
    [anon_sym_tcp] = ACTIONS(139),
    [anon_sym_udp] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(137),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(139),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(139),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(139),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(137),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(137),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(137),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(137),
    [anon_sym_ssl] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(137),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(137),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(137),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(137),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(137),
    [anon_sym_sip] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(137),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(137),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(137),
  },
  [11] = {
    [ts_builtin_sym_end] = ACTIONS(141),
    [anon_sym_AMP_AMP] = ACTIONS(143),
    [anon_sym_and] = ACTIONS(143),
    [anon_sym_xor] = ACTIONS(145),
    [anon_sym_CARET_CARET] = ACTIONS(145),
    [anon_sym_or] = ACTIONS(141),
    [anon_sym_PIPE_PIPE] = ACTIONS(141),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(141),
    [anon_sym_LPAREN] = ACTIONS(141),
    [anon_sym_RPAREN] = ACTIONS(141),
    [anon_sym_lookup_json_string] = ACTIONS(141),
    [anon_sym_lower] = ACTIONS(141),
    [anon_sym_regex_replace] = ACTIONS(141),
    [anon_sym_remove_bytes] = ACTIONS(141),
    [anon_sym_to_string] = ACTIONS(141),
    [anon_sym_upper] = ACTIONS(141),
    [anon_sym_url_decode] = ACTIONS(141),
    [anon_sym_uuidv4] = ACTIONS(141),
    [anon_sym_len] = ACTIONS(141),
    [anon_sym_ends_with] = ACTIONS(141),
    [anon_sym_starts_with] = ACTIONS(141),
    [anon_sym_any] = ACTIONS(141),
    [anon_sym_all] = ACTIONS(141),
    [anon_sym_true] = ACTIONS(141),
    [anon_sym_false] = ACTIONS(141),
    [anon_sym_not] = ACTIONS(141),
    [anon_sym_BANG] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(141),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(141),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(141),
    [anon_sym_icmp_DOTtype] = ACTIONS(141),
    [anon_sym_icmp_DOTcode] = ACTIONS(141),
    [anon_sym_ip_DOThdr_len] = ACTIONS(141),
    [anon_sym_ip_DOTlen] = ACTIONS(141),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(141),
    [anon_sym_ip_DOTttl] = ACTIONS(141),
    [anon_sym_tcp_DOTflags] = ACTIONS(147),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(141),
    [anon_sym_tcp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTsrcport] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc] = ACTIONS(147),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(141),
    [anon_sym_ip_DOTdst] = ACTIONS(147),
    [anon_sym_http_DOTcookie] = ACTIONS(141),
    [anon_sym_http_DOThost] = ACTIONS(141),
    [anon_sym_http_DOTreferer] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_http_DOTuser_agent] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(141),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(141),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(141),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(141),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(141),
    [anon_sym_icmp] = ACTIONS(147),
    [anon_sym_ip] = ACTIONS(147),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(141),
    [anon_sym_tcp] = ACTIONS(147),
    [anon_sym_udp] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(141),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(147),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(141),
    [anon_sym_ssl] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(141),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(141),
    [anon_sym_sip] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(141),
  },
  [12] = {
    [ts_builtin_sym_end] = ACTIONS(141),
    [anon_sym_AMP_AMP] = ACTIONS(141),
    [anon_sym_and] = ACTIONS(141),
    [anon_sym_xor] = ACTIONS(141),
    [anon_sym_CARET_CARET] = ACTIONS(141),
    [anon_sym_or] = ACTIONS(141),
    [anon_sym_PIPE_PIPE] = ACTIONS(141),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(141),
    [anon_sym_LPAREN] = ACTIONS(141),
    [anon_sym_RPAREN] = ACTIONS(141),
    [anon_sym_lookup_json_string] = ACTIONS(141),
    [anon_sym_lower] = ACTIONS(141),
    [anon_sym_regex_replace] = ACTIONS(141),
    [anon_sym_remove_bytes] = ACTIONS(141),
    [anon_sym_to_string] = ACTIONS(141),
    [anon_sym_upper] = ACTIONS(141),
    [anon_sym_url_decode] = ACTIONS(141),
    [anon_sym_uuidv4] = ACTIONS(141),
    [anon_sym_len] = ACTIONS(141),
    [anon_sym_ends_with] = ACTIONS(141),
    [anon_sym_starts_with] = ACTIONS(141),
    [anon_sym_any] = ACTIONS(141),
    [anon_sym_all] = ACTIONS(141),
    [anon_sym_true] = ACTIONS(141),
    [anon_sym_false] = ACTIONS(141),
    [anon_sym_not] = ACTIONS(141),
    [anon_sym_BANG] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(141),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(141),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(141),
    [anon_sym_icmp_DOTtype] = ACTIONS(141),
    [anon_sym_icmp_DOTcode] = ACTIONS(141),
    [anon_sym_ip_DOThdr_len] = ACTIONS(141),
    [anon_sym_ip_DOTlen] = ACTIONS(141),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(141),
    [anon_sym_ip_DOTttl] = ACTIONS(141),
    [anon_sym_tcp_DOTflags] = ACTIONS(147),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(141),
    [anon_sym_tcp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTsrcport] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc] = ACTIONS(147),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(141),
    [anon_sym_ip_DOTdst] = ACTIONS(147),
    [anon_sym_http_DOTcookie] = ACTIONS(141),
    [anon_sym_http_DOThost] = ACTIONS(141),
    [anon_sym_http_DOTreferer] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_http_DOTuser_agent] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(141),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(141),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(141),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(141),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(141),
    [anon_sym_icmp] = ACTIONS(147),
    [anon_sym_ip] = ACTIONS(147),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(141),
    [anon_sym_tcp] = ACTIONS(147),
    [anon_sym_udp] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(141),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(147),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(141),
    [anon_sym_ssl] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(141),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(141),
    [anon_sym_sip] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(141),
  },
  [13] = {
    [ts_builtin_sym_end] = ACTIONS(149),
    [anon_sym_AMP_AMP] = ACTIONS(149),
    [anon_sym_and] = ACTIONS(149),
    [anon_sym_xor] = ACTIONS(149),
    [anon_sym_CARET_CARET] = ACTIONS(149),
    [anon_sym_or] = ACTIONS(149),
    [anon_sym_PIPE_PIPE] = ACTIONS(149),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(149),
    [anon_sym_LPAREN] = ACTIONS(149),
    [anon_sym_RPAREN] = ACTIONS(149),
    [anon_sym_lookup_json_string] = ACTIONS(149),
    [anon_sym_lower] = ACTIONS(149),
    [anon_sym_regex_replace] = ACTIONS(149),
    [anon_sym_remove_bytes] = ACTIONS(149),
    [anon_sym_to_string] = ACTIONS(149),
    [anon_sym_upper] = ACTIONS(149),
    [anon_sym_url_decode] = ACTIONS(149),
    [anon_sym_uuidv4] = ACTIONS(149),
    [anon_sym_len] = ACTIONS(149),
    [anon_sym_ends_with] = ACTIONS(149),
    [anon_sym_starts_with] = ACTIONS(149),
    [anon_sym_any] = ACTIONS(149),
    [anon_sym_all] = ACTIONS(149),
    [anon_sym_true] = ACTIONS(149),
    [anon_sym_false] = ACTIONS(149),
    [anon_sym_not] = ACTIONS(149),
    [anon_sym_BANG] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(149),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(149),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(149),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(151),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(149),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(149),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(149),
    [anon_sym_icmp_DOTtype] = ACTIONS(149),
    [anon_sym_icmp_DOTcode] = ACTIONS(149),
    [anon_sym_ip_DOThdr_len] = ACTIONS(149),
    [anon_sym_ip_DOTlen] = ACTIONS(149),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(149),
    [anon_sym_ip_DOTttl] = ACTIONS(149),
    [anon_sym_tcp_DOTflags] = ACTIONS(151),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(149),
    [anon_sym_tcp_DOTdstport] = ACTIONS(149),
    [anon_sym_udp_DOTdstport] = ACTIONS(149),
    [anon_sym_udp_DOTsrcport] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(149),
    [anon_sym_ip_DOTsrc] = ACTIONS(151),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(149),
    [anon_sym_ip_DOTdst] = ACTIONS(151),
    [anon_sym_http_DOTcookie] = ACTIONS(149),
    [anon_sym_http_DOThost] = ACTIONS(149),
    [anon_sym_http_DOTreferer] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(149),
    [anon_sym_http_DOTuser_agent] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(149),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(151),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(149),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(149),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(149),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(149),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(149),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(149),
    [anon_sym_icmp] = ACTIONS(151),
    [anon_sym_ip] = ACTIONS(151),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(149),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(149),
    [anon_sym_tcp] = ACTIONS(151),
    [anon_sym_udp] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(149),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(151),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(151),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(151),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(149),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(149),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(149),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(149),
    [anon_sym_ssl] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(149),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(149),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(149),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(149),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(149),
    [anon_sym_sip] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(149),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(149),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(149),
  },
  [14] = {
    [ts_builtin_sym_end] = ACTIONS(153),
    [anon_sym_AMP_AMP] = ACTIONS(153),
    [anon_sym_and] = ACTIONS(153),
    [anon_sym_xor] = ACTIONS(153),
    [anon_sym_CARET_CARET] = ACTIONS(153),
    [anon_sym_or] = ACTIONS(153),
    [anon_sym_PIPE_PIPE] = ACTIONS(153),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(153),
    [anon_sym_LPAREN] = ACTIONS(153),
    [anon_sym_RPAREN] = ACTIONS(153),
    [anon_sym_lookup_json_string] = ACTIONS(153),
    [anon_sym_lower] = ACTIONS(153),
    [anon_sym_regex_replace] = ACTIONS(153),
    [anon_sym_remove_bytes] = ACTIONS(153),
    [anon_sym_to_string] = ACTIONS(153),
    [anon_sym_upper] = ACTIONS(153),
    [anon_sym_url_decode] = ACTIONS(153),
    [anon_sym_uuidv4] = ACTIONS(153),
    [anon_sym_len] = ACTIONS(153),
    [anon_sym_ends_with] = ACTIONS(153),
    [anon_sym_starts_with] = ACTIONS(153),
    [anon_sym_any] = ACTIONS(153),
    [anon_sym_all] = ACTIONS(153),
    [anon_sym_true] = ACTIONS(153),
    [anon_sym_false] = ACTIONS(153),
    [anon_sym_not] = ACTIONS(153),
    [anon_sym_BANG] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(153),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(153),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(155),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(153),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(153),
    [anon_sym_icmp_DOTtype] = ACTIONS(153),
    [anon_sym_icmp_DOTcode] = ACTIONS(153),
    [anon_sym_ip_DOThdr_len] = ACTIONS(153),
    [anon_sym_ip_DOTlen] = ACTIONS(153),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(153),
    [anon_sym_ip_DOTttl] = ACTIONS(153),
    [anon_sym_tcp_DOTflags] = ACTIONS(155),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(153),
    [anon_sym_tcp_DOTdstport] = ACTIONS(153),
    [anon_sym_udp_DOTdstport] = ACTIONS(153),
    [anon_sym_udp_DOTsrcport] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(153),
    [anon_sym_ip_DOTsrc] = ACTIONS(155),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(153),
    [anon_sym_ip_DOTdst] = ACTIONS(155),
    [anon_sym_http_DOTcookie] = ACTIONS(153),
    [anon_sym_http_DOThost] = ACTIONS(153),
    [anon_sym_http_DOTreferer] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(153),
    [anon_sym_http_DOTuser_agent] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(153),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(155),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(153),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(153),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(153),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(153),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(153),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(153),
    [anon_sym_icmp] = ACTIONS(155),
    [anon_sym_ip] = ACTIONS(155),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(153),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(153),
    [anon_sym_tcp] = ACTIONS(155),
    [anon_sym_udp] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(153),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(155),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(155),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(155),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(153),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(153),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(153),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(153),
    [anon_sym_ssl] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(153),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(153),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(153),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(153),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(153),
    [anon_sym_sip] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(153),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(153),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(153),
  },
  [15] = {
    [ts_builtin_sym_end] = ACTIONS(157),
    [anon_sym_AMP_AMP] = ACTIONS(157),
    [anon_sym_and] = ACTIONS(157),
    [anon_sym_xor] = ACTIONS(157),
    [anon_sym_CARET_CARET] = ACTIONS(157),
    [anon_sym_or] = ACTIONS(157),
    [anon_sym_PIPE_PIPE] = ACTIONS(157),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(157),
    [anon_sym_LPAREN] = ACTIONS(157),
    [anon_sym_RPAREN] = ACTIONS(157),
    [anon_sym_lookup_json_string] = ACTIONS(157),
    [anon_sym_lower] = ACTIONS(157),
    [anon_sym_regex_replace] = ACTIONS(157),
    [anon_sym_remove_bytes] = ACTIONS(157),
    [anon_sym_to_string] = ACTIONS(157),
    [anon_sym_upper] = ACTIONS(157),
    [anon_sym_url_decode] = ACTIONS(157),
    [anon_sym_uuidv4] = ACTIONS(157),
    [anon_sym_len] = ACTIONS(157),
    [anon_sym_ends_with] = ACTIONS(157),
    [anon_sym_starts_with] = ACTIONS(157),
    [anon_sym_any] = ACTIONS(157),
    [anon_sym_all] = ACTIONS(157),
    [anon_sym_true] = ACTIONS(157),
    [anon_sym_false] = ACTIONS(157),
    [anon_sym_not] = ACTIONS(157),
    [anon_sym_BANG] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(157),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(157),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(159),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(157),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(157),
    [anon_sym_icmp_DOTtype] = ACTIONS(157),
    [anon_sym_icmp_DOTcode] = ACTIONS(157),
    [anon_sym_ip_DOThdr_len] = ACTIONS(157),
    [anon_sym_ip_DOTlen] = ACTIONS(157),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(157),
    [anon_sym_ip_DOTttl] = ACTIONS(157),
    [anon_sym_tcp_DOTflags] = ACTIONS(159),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(157),
    [anon_sym_tcp_DOTdstport] = ACTIONS(157),
    [anon_sym_udp_DOTdstport] = ACTIONS(157),
    [anon_sym_udp_DOTsrcport] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(157),
    [anon_sym_ip_DOTsrc] = ACTIONS(159),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(157),
    [anon_sym_ip_DOTdst] = ACTIONS(159),
    [anon_sym_http_DOTcookie] = ACTIONS(157),
    [anon_sym_http_DOThost] = ACTIONS(157),
    [anon_sym_http_DOTreferer] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(157),
    [anon_sym_http_DOTuser_agent] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(157),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(159),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(159),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(157),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(157),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(157),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(157),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(157),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(157),
    [anon_sym_icmp] = ACTIONS(159),
    [anon_sym_ip] = ACTIONS(159),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(157),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(157),
    [anon_sym_tcp] = ACTIONS(159),
    [anon_sym_udp] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(157),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(159),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(159),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(159),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(157),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(157),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(157),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(157),
    [anon_sym_ssl] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(157),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(157),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(157),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(157),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(157),
    [anon_sym_sip] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(157),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(157),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(157),
  },
  [16] = {
    [ts_builtin_sym_end] = ACTIONS(161),
    [anon_sym_AMP_AMP] = ACTIONS(161),
    [anon_sym_and] = ACTIONS(161),
    [anon_sym_xor] = ACTIONS(161),
    [anon_sym_CARET_CARET] = ACTIONS(161),
    [anon_sym_or] = ACTIONS(161),
    [anon_sym_PIPE_PIPE] = ACTIONS(161),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(161),
    [anon_sym_LPAREN] = ACTIONS(161),
    [anon_sym_RPAREN] = ACTIONS(161),
    [anon_sym_lookup_json_string] = ACTIONS(161),
    [anon_sym_lower] = ACTIONS(161),
    [anon_sym_regex_replace] = ACTIONS(161),
    [anon_sym_remove_bytes] = ACTIONS(161),
    [anon_sym_to_string] = ACTIONS(161),
    [anon_sym_upper] = ACTIONS(161),
    [anon_sym_url_decode] = ACTIONS(161),
    [anon_sym_uuidv4] = ACTIONS(161),
    [anon_sym_len] = ACTIONS(161),
    [anon_sym_ends_with] = ACTIONS(161),
    [anon_sym_starts_with] = ACTIONS(161),
    [anon_sym_any] = ACTIONS(161),
    [anon_sym_all] = ACTIONS(161),
    [anon_sym_true] = ACTIONS(161),
    [anon_sym_false] = ACTIONS(161),
    [anon_sym_not] = ACTIONS(161),
    [anon_sym_BANG] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(161),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(161),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(161),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(163),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(161),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(161),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(161),
    [anon_sym_icmp_DOTtype] = ACTIONS(161),
    [anon_sym_icmp_DOTcode] = ACTIONS(161),
    [anon_sym_ip_DOThdr_len] = ACTIONS(161),
    [anon_sym_ip_DOTlen] = ACTIONS(161),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(161),
    [anon_sym_ip_DOTttl] = ACTIONS(161),
    [anon_sym_tcp_DOTflags] = ACTIONS(163),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(161),
    [anon_sym_tcp_DOTdstport] = ACTIONS(161),
    [anon_sym_udp_DOTdstport] = ACTIONS(161),
    [anon_sym_udp_DOTsrcport] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(161),
    [anon_sym_ip_DOTsrc] = ACTIONS(163),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(161),
    [anon_sym_ip_DOTdst] = ACTIONS(163),
    [anon_sym_http_DOTcookie] = ACTIONS(161),
    [anon_sym_http_DOThost] = ACTIONS(161),
    [anon_sym_http_DOTreferer] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(161),
    [anon_sym_http_DOTuser_agent] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(161),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(163),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(161),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(161),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(161),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(161),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(161),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(161),
    [anon_sym_icmp] = ACTIONS(163),
    [anon_sym_ip] = ACTIONS(163),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(161),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(161),
    [anon_sym_tcp] = ACTIONS(163),
    [anon_sym_udp] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(161),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(163),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(163),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(163),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(161),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(161),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(161),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(161),
    [anon_sym_ssl] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(161),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(161),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(161),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(161),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(161),
    [anon_sym_sip] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(161),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(161),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(161),
  },
  [17] = {
    [ts_builtin_sym_end] = ACTIONS(165),
    [anon_sym_AMP_AMP] = ACTIONS(165),
    [anon_sym_and] = ACTIONS(165),
    [anon_sym_xor] = ACTIONS(165),
    [anon_sym_CARET_CARET] = ACTIONS(165),
    [anon_sym_or] = ACTIONS(165),
    [anon_sym_PIPE_PIPE] = ACTIONS(165),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(165),
    [anon_sym_LPAREN] = ACTIONS(165),
    [anon_sym_RPAREN] = ACTIONS(165),
    [anon_sym_lookup_json_string] = ACTIONS(165),
    [anon_sym_lower] = ACTIONS(165),
    [anon_sym_regex_replace] = ACTIONS(165),
    [anon_sym_remove_bytes] = ACTIONS(165),
    [anon_sym_to_string] = ACTIONS(165),
    [anon_sym_upper] = ACTIONS(165),
    [anon_sym_url_decode] = ACTIONS(165),
    [anon_sym_uuidv4] = ACTIONS(165),
    [anon_sym_len] = ACTIONS(165),
    [anon_sym_ends_with] = ACTIONS(165),
    [anon_sym_starts_with] = ACTIONS(165),
    [anon_sym_any] = ACTIONS(165),
    [anon_sym_all] = ACTIONS(165),
    [anon_sym_true] = ACTIONS(165),
    [anon_sym_false] = ACTIONS(165),
    [anon_sym_not] = ACTIONS(165),
    [anon_sym_BANG] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(165),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(165),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(165),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(167),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(165),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(165),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(165),
    [anon_sym_icmp_DOTtype] = ACTIONS(165),
    [anon_sym_icmp_DOTcode] = ACTIONS(165),
    [anon_sym_ip_DOThdr_len] = ACTIONS(165),
    [anon_sym_ip_DOTlen] = ACTIONS(165),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(165),
    [anon_sym_ip_DOTttl] = ACTIONS(165),
    [anon_sym_tcp_DOTflags] = ACTIONS(167),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(165),
    [anon_sym_tcp_DOTdstport] = ACTIONS(165),
    [anon_sym_udp_DOTdstport] = ACTIONS(165),
    [anon_sym_udp_DOTsrcport] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(165),
    [anon_sym_ip_DOTsrc] = ACTIONS(167),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(165),
    [anon_sym_ip_DOTdst] = ACTIONS(167),
    [anon_sym_http_DOTcookie] = ACTIONS(165),
    [anon_sym_http_DOThost] = ACTIONS(165),
    [anon_sym_http_DOTreferer] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(165),
    [anon_sym_http_DOTuser_agent] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(165),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(167),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(165),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(165),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(165),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(165),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(165),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(165),
    [anon_sym_icmp] = ACTIONS(167),
    [anon_sym_ip] = ACTIONS(167),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(165),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(165),
    [anon_sym_tcp] = ACTIONS(167),
    [anon_sym_udp] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(165),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(167),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(167),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(167),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(165),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(165),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(165),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(165),
    [anon_sym_ssl] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(165),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(165),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(165),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(165),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(165),
    [anon_sym_sip] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(165),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(165),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(165),
  },
  [18] = {
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
    [anon_sym_lookup_json_string] = ACTIONS(169),
    [anon_sym_lower] = ACTIONS(169),
    [anon_sym_regex_replace] = ACTIONS(169),
    [anon_sym_remove_bytes] = ACTIONS(169),
    [anon_sym_to_string] = ACTIONS(169),
    [anon_sym_upper] = ACTIONS(169),
    [anon_sym_url_decode] = ACTIONS(169),
    [anon_sym_uuidv4] = ACTIONS(169),
    [anon_sym_len] = ACTIONS(169),
    [anon_sym_ends_with] = ACTIONS(169),
    [anon_sym_starts_with] = ACTIONS(169),
    [anon_sym_any] = ACTIONS(169),
    [anon_sym_all] = ACTIONS(169),
    [anon_sym_true] = ACTIONS(169),
    [anon_sym_false] = ACTIONS(169),
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
    [anon_sym_icmp_DOTtype] = ACTIONS(169),
    [anon_sym_icmp_DOTcode] = ACTIONS(169),
    [anon_sym_ip_DOThdr_len] = ACTIONS(169),
    [anon_sym_ip_DOTlen] = ACTIONS(169),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(169),
    [anon_sym_ip_DOTttl] = ACTIONS(169),
    [anon_sym_tcp_DOTflags] = ACTIONS(171),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(169),
    [anon_sym_tcp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTdstport] = ACTIONS(169),
    [anon_sym_udp_DOTsrcport] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc] = ACTIONS(171),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(169),
    [anon_sym_ip_DOTdst] = ACTIONS(171),
    [anon_sym_http_DOTcookie] = ACTIONS(169),
    [anon_sym_http_DOThost] = ACTIONS(169),
    [anon_sym_http_DOTreferer] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_http_DOTuser_agent] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(169),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(171),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(169),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(169),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(169),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(169),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(169),
    [anon_sym_icmp] = ACTIONS(171),
    [anon_sym_ip] = ACTIONS(171),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(169),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(169),
    [anon_sym_tcp] = ACTIONS(171),
    [anon_sym_udp] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(169),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(171),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(171),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(171),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(169),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(169),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(169),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(169),
    [anon_sym_ssl] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(169),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(169),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(169),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(169),
    [anon_sym_sip] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(169),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(169),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(169),
  },
  [19] = {
    [ts_builtin_sym_end] = ACTIONS(173),
    [anon_sym_AMP_AMP] = ACTIONS(173),
    [anon_sym_and] = ACTIONS(173),
    [anon_sym_xor] = ACTIONS(173),
    [anon_sym_CARET_CARET] = ACTIONS(173),
    [anon_sym_or] = ACTIONS(173),
    [anon_sym_PIPE_PIPE] = ACTIONS(173),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(173),
    [anon_sym_LPAREN] = ACTIONS(173),
    [anon_sym_RPAREN] = ACTIONS(173),
    [anon_sym_lookup_json_string] = ACTIONS(173),
    [anon_sym_lower] = ACTIONS(173),
    [anon_sym_regex_replace] = ACTIONS(173),
    [anon_sym_remove_bytes] = ACTIONS(173),
    [anon_sym_to_string] = ACTIONS(173),
    [anon_sym_upper] = ACTIONS(173),
    [anon_sym_url_decode] = ACTIONS(173),
    [anon_sym_uuidv4] = ACTIONS(173),
    [anon_sym_len] = ACTIONS(173),
    [anon_sym_ends_with] = ACTIONS(173),
    [anon_sym_starts_with] = ACTIONS(173),
    [anon_sym_any] = ACTIONS(173),
    [anon_sym_all] = ACTIONS(173),
    [anon_sym_true] = ACTIONS(173),
    [anon_sym_false] = ACTIONS(173),
    [anon_sym_not] = ACTIONS(173),
    [anon_sym_BANG] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(173),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(173),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(173),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(175),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(173),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(173),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(173),
    [anon_sym_icmp_DOTtype] = ACTIONS(173),
    [anon_sym_icmp_DOTcode] = ACTIONS(173),
    [anon_sym_ip_DOThdr_len] = ACTIONS(173),
    [anon_sym_ip_DOTlen] = ACTIONS(173),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(173),
    [anon_sym_ip_DOTttl] = ACTIONS(173),
    [anon_sym_tcp_DOTflags] = ACTIONS(175),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(173),
    [anon_sym_tcp_DOTdstport] = ACTIONS(173),
    [anon_sym_udp_DOTdstport] = ACTIONS(173),
    [anon_sym_udp_DOTsrcport] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(173),
    [anon_sym_ip_DOTsrc] = ACTIONS(175),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(173),
    [anon_sym_ip_DOTdst] = ACTIONS(175),
    [anon_sym_http_DOTcookie] = ACTIONS(173),
    [anon_sym_http_DOThost] = ACTIONS(173),
    [anon_sym_http_DOTreferer] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(173),
    [anon_sym_http_DOTuser_agent] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(173),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(175),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(175),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(173),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(173),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(173),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(173),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(173),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(173),
    [anon_sym_icmp] = ACTIONS(175),
    [anon_sym_ip] = ACTIONS(175),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(173),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(173),
    [anon_sym_tcp] = ACTIONS(175),
    [anon_sym_udp] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(173),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(175),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(175),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(175),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(173),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(173),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(173),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(173),
    [anon_sym_ssl] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(173),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(173),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(173),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(173),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(173),
    [anon_sym_sip] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(173),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(173),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(173),
  },
  [20] = {
    [ts_builtin_sym_end] = ACTIONS(177),
    [anon_sym_AMP_AMP] = ACTIONS(177),
    [anon_sym_and] = ACTIONS(177),
    [anon_sym_xor] = ACTIONS(177),
    [anon_sym_CARET_CARET] = ACTIONS(177),
    [anon_sym_or] = ACTIONS(177),
    [anon_sym_PIPE_PIPE] = ACTIONS(177),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(177),
    [anon_sym_LPAREN] = ACTIONS(177),
    [anon_sym_RPAREN] = ACTIONS(177),
    [anon_sym_lookup_json_string] = ACTIONS(177),
    [anon_sym_lower] = ACTIONS(177),
    [anon_sym_regex_replace] = ACTIONS(177),
    [anon_sym_remove_bytes] = ACTIONS(177),
    [anon_sym_to_string] = ACTIONS(177),
    [anon_sym_upper] = ACTIONS(177),
    [anon_sym_url_decode] = ACTIONS(177),
    [anon_sym_uuidv4] = ACTIONS(177),
    [anon_sym_len] = ACTIONS(177),
    [anon_sym_ends_with] = ACTIONS(177),
    [anon_sym_starts_with] = ACTIONS(177),
    [anon_sym_any] = ACTIONS(177),
    [anon_sym_all] = ACTIONS(177),
    [anon_sym_true] = ACTIONS(177),
    [anon_sym_false] = ACTIONS(177),
    [anon_sym_not] = ACTIONS(177),
    [anon_sym_BANG] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(177),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(177),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(177),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(179),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(177),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(177),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(177),
    [anon_sym_icmp_DOTtype] = ACTIONS(177),
    [anon_sym_icmp_DOTcode] = ACTIONS(177),
    [anon_sym_ip_DOThdr_len] = ACTIONS(177),
    [anon_sym_ip_DOTlen] = ACTIONS(177),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(177),
    [anon_sym_ip_DOTttl] = ACTIONS(177),
    [anon_sym_tcp_DOTflags] = ACTIONS(179),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(177),
    [anon_sym_tcp_DOTdstport] = ACTIONS(177),
    [anon_sym_udp_DOTdstport] = ACTIONS(177),
    [anon_sym_udp_DOTsrcport] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(177),
    [anon_sym_ip_DOTsrc] = ACTIONS(179),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(177),
    [anon_sym_ip_DOTdst] = ACTIONS(179),
    [anon_sym_http_DOTcookie] = ACTIONS(177),
    [anon_sym_http_DOThost] = ACTIONS(177),
    [anon_sym_http_DOTreferer] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(177),
    [anon_sym_http_DOTuser_agent] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(177),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(179),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(177),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(177),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(177),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(177),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(177),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(177),
    [anon_sym_icmp] = ACTIONS(179),
    [anon_sym_ip] = ACTIONS(179),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(177),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(177),
    [anon_sym_tcp] = ACTIONS(179),
    [anon_sym_udp] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(177),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(179),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(179),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(177),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(177),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(177),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(177),
    [anon_sym_ssl] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(177),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(177),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(177),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(177),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(177),
    [anon_sym_sip] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(177),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(177),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(177),
  },
  [21] = {
    [ts_builtin_sym_end] = ACTIONS(181),
    [anon_sym_AMP_AMP] = ACTIONS(181),
    [anon_sym_and] = ACTIONS(181),
    [anon_sym_xor] = ACTIONS(181),
    [anon_sym_CARET_CARET] = ACTIONS(181),
    [anon_sym_or] = ACTIONS(181),
    [anon_sym_PIPE_PIPE] = ACTIONS(181),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(181),
    [anon_sym_LPAREN] = ACTIONS(181),
    [anon_sym_RPAREN] = ACTIONS(181),
    [anon_sym_lookup_json_string] = ACTIONS(181),
    [anon_sym_lower] = ACTIONS(181),
    [anon_sym_regex_replace] = ACTIONS(181),
    [anon_sym_remove_bytes] = ACTIONS(181),
    [anon_sym_to_string] = ACTIONS(181),
    [anon_sym_upper] = ACTIONS(181),
    [anon_sym_url_decode] = ACTIONS(181),
    [anon_sym_uuidv4] = ACTIONS(181),
    [anon_sym_len] = ACTIONS(181),
    [anon_sym_ends_with] = ACTIONS(181),
    [anon_sym_starts_with] = ACTIONS(181),
    [anon_sym_any] = ACTIONS(181),
    [anon_sym_all] = ACTIONS(181),
    [anon_sym_true] = ACTIONS(181),
    [anon_sym_false] = ACTIONS(181),
    [anon_sym_not] = ACTIONS(181),
    [anon_sym_BANG] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(181),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(181),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(183),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(181),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(181),
    [anon_sym_icmp_DOTtype] = ACTIONS(181),
    [anon_sym_icmp_DOTcode] = ACTIONS(181),
    [anon_sym_ip_DOThdr_len] = ACTIONS(181),
    [anon_sym_ip_DOTlen] = ACTIONS(181),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(181),
    [anon_sym_ip_DOTttl] = ACTIONS(181),
    [anon_sym_tcp_DOTflags] = ACTIONS(183),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(181),
    [anon_sym_tcp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTdstport] = ACTIONS(181),
    [anon_sym_udp_DOTsrcport] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc] = ACTIONS(183),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(181),
    [anon_sym_ip_DOTdst] = ACTIONS(183),
    [anon_sym_http_DOTcookie] = ACTIONS(181),
    [anon_sym_http_DOThost] = ACTIONS(181),
    [anon_sym_http_DOTreferer] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_http_DOTuser_agent] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(181),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(183),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(181),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(181),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(181),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(181),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(181),
    [anon_sym_icmp] = ACTIONS(183),
    [anon_sym_ip] = ACTIONS(183),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(181),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(181),
    [anon_sym_tcp] = ACTIONS(183),
    [anon_sym_udp] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(181),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(183),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(183),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(181),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(181),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(181),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(181),
    [anon_sym_ssl] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(181),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(181),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(181),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(181),
    [anon_sym_sip] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(181),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(181),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(181),
  },
  [22] = {
    [ts_builtin_sym_end] = ACTIONS(185),
    [anon_sym_AMP_AMP] = ACTIONS(185),
    [anon_sym_and] = ACTIONS(185),
    [anon_sym_xor] = ACTIONS(185),
    [anon_sym_CARET_CARET] = ACTIONS(185),
    [anon_sym_or] = ACTIONS(185),
    [anon_sym_PIPE_PIPE] = ACTIONS(185),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(185),
    [anon_sym_LPAREN] = ACTIONS(185),
    [anon_sym_RPAREN] = ACTIONS(185),
    [anon_sym_lookup_json_string] = ACTIONS(185),
    [anon_sym_lower] = ACTIONS(185),
    [anon_sym_regex_replace] = ACTIONS(185),
    [anon_sym_remove_bytes] = ACTIONS(185),
    [anon_sym_to_string] = ACTIONS(185),
    [anon_sym_upper] = ACTIONS(185),
    [anon_sym_url_decode] = ACTIONS(185),
    [anon_sym_uuidv4] = ACTIONS(185),
    [anon_sym_len] = ACTIONS(185),
    [anon_sym_ends_with] = ACTIONS(185),
    [anon_sym_starts_with] = ACTIONS(185),
    [anon_sym_any] = ACTIONS(185),
    [anon_sym_all] = ACTIONS(185),
    [anon_sym_true] = ACTIONS(185),
    [anon_sym_false] = ACTIONS(185),
    [anon_sym_not] = ACTIONS(185),
    [anon_sym_BANG] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(185),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(185),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(185),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(187),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(185),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(185),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(185),
    [anon_sym_icmp_DOTtype] = ACTIONS(185),
    [anon_sym_icmp_DOTcode] = ACTIONS(185),
    [anon_sym_ip_DOThdr_len] = ACTIONS(185),
    [anon_sym_ip_DOTlen] = ACTIONS(185),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(185),
    [anon_sym_ip_DOTttl] = ACTIONS(185),
    [anon_sym_tcp_DOTflags] = ACTIONS(187),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(185),
    [anon_sym_tcp_DOTdstport] = ACTIONS(185),
    [anon_sym_udp_DOTdstport] = ACTIONS(185),
    [anon_sym_udp_DOTsrcport] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(185),
    [anon_sym_ip_DOTsrc] = ACTIONS(187),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(185),
    [anon_sym_ip_DOTdst] = ACTIONS(187),
    [anon_sym_http_DOTcookie] = ACTIONS(185),
    [anon_sym_http_DOThost] = ACTIONS(185),
    [anon_sym_http_DOTreferer] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(185),
    [anon_sym_http_DOTuser_agent] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(185),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(187),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(185),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(185),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(185),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(185),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(185),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(185),
    [anon_sym_icmp] = ACTIONS(187),
    [anon_sym_ip] = ACTIONS(187),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(185),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(185),
    [anon_sym_tcp] = ACTIONS(187),
    [anon_sym_udp] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(185),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(187),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(187),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(187),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(185),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(185),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(185),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(185),
    [anon_sym_ssl] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(185),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(185),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(185),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(185),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(185),
    [anon_sym_sip] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(185),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(185),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(185),
  },
  [23] = {
    [ts_builtin_sym_end] = ACTIONS(141),
    [anon_sym_AMP_AMP] = ACTIONS(143),
    [anon_sym_and] = ACTIONS(143),
    [anon_sym_xor] = ACTIONS(141),
    [anon_sym_CARET_CARET] = ACTIONS(141),
    [anon_sym_or] = ACTIONS(141),
    [anon_sym_PIPE_PIPE] = ACTIONS(141),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(141),
    [anon_sym_LPAREN] = ACTIONS(141),
    [anon_sym_RPAREN] = ACTIONS(141),
    [anon_sym_lookup_json_string] = ACTIONS(141),
    [anon_sym_lower] = ACTIONS(141),
    [anon_sym_regex_replace] = ACTIONS(141),
    [anon_sym_remove_bytes] = ACTIONS(141),
    [anon_sym_to_string] = ACTIONS(141),
    [anon_sym_upper] = ACTIONS(141),
    [anon_sym_url_decode] = ACTIONS(141),
    [anon_sym_uuidv4] = ACTIONS(141),
    [anon_sym_len] = ACTIONS(141),
    [anon_sym_ends_with] = ACTIONS(141),
    [anon_sym_starts_with] = ACTIONS(141),
    [anon_sym_any] = ACTIONS(141),
    [anon_sym_all] = ACTIONS(141),
    [anon_sym_true] = ACTIONS(141),
    [anon_sym_false] = ACTIONS(141),
    [anon_sym_not] = ACTIONS(141),
    [anon_sym_BANG] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(141),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(141),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(147),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(141),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(141),
    [anon_sym_icmp_DOTtype] = ACTIONS(141),
    [anon_sym_icmp_DOTcode] = ACTIONS(141),
    [anon_sym_ip_DOThdr_len] = ACTIONS(141),
    [anon_sym_ip_DOTlen] = ACTIONS(141),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(141),
    [anon_sym_ip_DOTttl] = ACTIONS(141),
    [anon_sym_tcp_DOTflags] = ACTIONS(147),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(141),
    [anon_sym_tcp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTdstport] = ACTIONS(141),
    [anon_sym_udp_DOTsrcport] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc] = ACTIONS(147),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(141),
    [anon_sym_ip_DOTdst] = ACTIONS(147),
    [anon_sym_http_DOTcookie] = ACTIONS(141),
    [anon_sym_http_DOThost] = ACTIONS(141),
    [anon_sym_http_DOTreferer] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_http_DOTuser_agent] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(141),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(147),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(141),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(141),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(141),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(141),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(141),
    [anon_sym_icmp] = ACTIONS(147),
    [anon_sym_ip] = ACTIONS(147),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(141),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(141),
    [anon_sym_tcp] = ACTIONS(147),
    [anon_sym_udp] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(141),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(147),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(147),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(141),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(141),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(141),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(141),
    [anon_sym_ssl] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(141),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(141),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(141),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(141),
    [anon_sym_sip] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(141),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(141),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(141),
  },
  [24] = {
    [ts_builtin_sym_end] = ACTIONS(189),
    [anon_sym_AMP_AMP] = ACTIONS(189),
    [anon_sym_and] = ACTIONS(189),
    [anon_sym_xor] = ACTIONS(189),
    [anon_sym_CARET_CARET] = ACTIONS(189),
    [anon_sym_or] = ACTIONS(189),
    [anon_sym_PIPE_PIPE] = ACTIONS(189),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(189),
    [anon_sym_LPAREN] = ACTIONS(189),
    [anon_sym_RPAREN] = ACTIONS(189),
    [anon_sym_lookup_json_string] = ACTIONS(189),
    [anon_sym_lower] = ACTIONS(189),
    [anon_sym_regex_replace] = ACTIONS(189),
    [anon_sym_remove_bytes] = ACTIONS(189),
    [anon_sym_to_string] = ACTIONS(189),
    [anon_sym_upper] = ACTIONS(189),
    [anon_sym_url_decode] = ACTIONS(189),
    [anon_sym_uuidv4] = ACTIONS(189),
    [anon_sym_len] = ACTIONS(189),
    [anon_sym_ends_with] = ACTIONS(189),
    [anon_sym_starts_with] = ACTIONS(189),
    [anon_sym_any] = ACTIONS(189),
    [anon_sym_all] = ACTIONS(189),
    [anon_sym_true] = ACTIONS(189),
    [anon_sym_false] = ACTIONS(189),
    [anon_sym_not] = ACTIONS(189),
    [anon_sym_BANG] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(189),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(189),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(189),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(191),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(189),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(189),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(189),
    [anon_sym_icmp_DOTtype] = ACTIONS(189),
    [anon_sym_icmp_DOTcode] = ACTIONS(189),
    [anon_sym_ip_DOThdr_len] = ACTIONS(189),
    [anon_sym_ip_DOTlen] = ACTIONS(189),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(189),
    [anon_sym_ip_DOTttl] = ACTIONS(189),
    [anon_sym_tcp_DOTflags] = ACTIONS(191),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(189),
    [anon_sym_tcp_DOTdstport] = ACTIONS(189),
    [anon_sym_udp_DOTdstport] = ACTIONS(189),
    [anon_sym_udp_DOTsrcport] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(189),
    [anon_sym_ip_DOTsrc] = ACTIONS(191),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(189),
    [anon_sym_ip_DOTdst] = ACTIONS(191),
    [anon_sym_http_DOTcookie] = ACTIONS(189),
    [anon_sym_http_DOThost] = ACTIONS(189),
    [anon_sym_http_DOTreferer] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(189),
    [anon_sym_http_DOTuser_agent] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(189),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(191),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(189),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(189),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(189),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(189),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(189),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(189),
    [anon_sym_icmp] = ACTIONS(191),
    [anon_sym_ip] = ACTIONS(191),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(189),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(189),
    [anon_sym_tcp] = ACTIONS(191),
    [anon_sym_udp] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(189),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(191),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(191),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(191),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(189),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(189),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(189),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(189),
    [anon_sym_ssl] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(189),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(189),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(189),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(189),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(189),
    [anon_sym_sip] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(189),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(189),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(189),
  },
  [25] = {
    [ts_builtin_sym_end] = ACTIONS(193),
    [anon_sym_AMP_AMP] = ACTIONS(193),
    [anon_sym_and] = ACTIONS(193),
    [anon_sym_xor] = ACTIONS(193),
    [anon_sym_CARET_CARET] = ACTIONS(193),
    [anon_sym_or] = ACTIONS(193),
    [anon_sym_PIPE_PIPE] = ACTIONS(193),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(193),
    [anon_sym_LPAREN] = ACTIONS(193),
    [anon_sym_RPAREN] = ACTIONS(193),
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
    [anon_sym_any] = ACTIONS(193),
    [anon_sym_all] = ACTIONS(193),
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
    [anon_sym_icmp_DOTtype] = ACTIONS(193),
    [anon_sym_icmp_DOTcode] = ACTIONS(193),
    [anon_sym_ip_DOThdr_len] = ACTIONS(193),
    [anon_sym_ip_DOTlen] = ACTIONS(193),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(193),
    [anon_sym_ip_DOTttl] = ACTIONS(193),
    [anon_sym_tcp_DOTflags] = ACTIONS(195),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(193),
    [anon_sym_tcp_DOTdstport] = ACTIONS(193),
    [anon_sym_udp_DOTdstport] = ACTIONS(193),
    [anon_sym_udp_DOTsrcport] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(193),
    [anon_sym_ip_DOTsrc] = ACTIONS(195),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(193),
    [anon_sym_ip_DOTdst] = ACTIONS(195),
    [anon_sym_http_DOTcookie] = ACTIONS(193),
    [anon_sym_http_DOThost] = ACTIONS(193),
    [anon_sym_http_DOTreferer] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(193),
    [anon_sym_http_DOTuser_agent] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(193),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(195),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(193),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(193),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(193),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(193),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(193),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(193),
    [anon_sym_icmp] = ACTIONS(195),
    [anon_sym_ip] = ACTIONS(195),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(193),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(193),
    [anon_sym_tcp] = ACTIONS(195),
    [anon_sym_udp] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(193),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(195),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(195),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(195),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(193),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(193),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(193),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(193),
    [anon_sym_ssl] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(193),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(193),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(193),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(193),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(193),
    [anon_sym_sip] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(193),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(193),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(193),
  },
  [26] = {
    [ts_builtin_sym_end] = ACTIONS(197),
    [anon_sym_AMP_AMP] = ACTIONS(197),
    [anon_sym_and] = ACTIONS(197),
    [anon_sym_xor] = ACTIONS(197),
    [anon_sym_CARET_CARET] = ACTIONS(197),
    [anon_sym_or] = ACTIONS(197),
    [anon_sym_PIPE_PIPE] = ACTIONS(197),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(197),
    [anon_sym_LPAREN] = ACTIONS(197),
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
    [anon_sym_any] = ACTIONS(197),
    [anon_sym_all] = ACTIONS(197),
    [anon_sym_true] = ACTIONS(197),
    [anon_sym_false] = ACTIONS(197),
    [anon_sym_not] = ACTIONS(197),
    [anon_sym_BANG] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(197),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(197),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(199),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(197),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(197),
    [anon_sym_icmp_DOTtype] = ACTIONS(197),
    [anon_sym_icmp_DOTcode] = ACTIONS(197),
    [anon_sym_ip_DOThdr_len] = ACTIONS(197),
    [anon_sym_ip_DOTlen] = ACTIONS(197),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(197),
    [anon_sym_ip_DOTttl] = ACTIONS(197),
    [anon_sym_tcp_DOTflags] = ACTIONS(199),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(197),
    [anon_sym_tcp_DOTdstport] = ACTIONS(197),
    [anon_sym_udp_DOTdstport] = ACTIONS(197),
    [anon_sym_udp_DOTsrcport] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(197),
    [anon_sym_ip_DOTsrc] = ACTIONS(199),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(197),
    [anon_sym_ip_DOTdst] = ACTIONS(199),
    [anon_sym_http_DOTcookie] = ACTIONS(197),
    [anon_sym_http_DOThost] = ACTIONS(197),
    [anon_sym_http_DOTreferer] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(197),
    [anon_sym_http_DOTuser_agent] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(197),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(199),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(197),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(197),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(197),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(197),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(197),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(197),
    [anon_sym_icmp] = ACTIONS(199),
    [anon_sym_ip] = ACTIONS(199),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(197),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(197),
    [anon_sym_tcp] = ACTIONS(199),
    [anon_sym_udp] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(197),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(199),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(199),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(199),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(197),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(197),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(197),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(197),
    [anon_sym_ssl] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(197),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(197),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(197),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(197),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(197),
    [anon_sym_sip] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(197),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(197),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(197),
  },
  [27] = {
    [ts_builtin_sym_end] = ACTIONS(201),
    [anon_sym_AMP_AMP] = ACTIONS(201),
    [anon_sym_and] = ACTIONS(201),
    [anon_sym_xor] = ACTIONS(201),
    [anon_sym_CARET_CARET] = ACTIONS(201),
    [anon_sym_or] = ACTIONS(201),
    [anon_sym_PIPE_PIPE] = ACTIONS(201),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(201),
    [anon_sym_LPAREN] = ACTIONS(201),
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
    [anon_sym_any] = ACTIONS(201),
    [anon_sym_all] = ACTIONS(201),
    [anon_sym_true] = ACTIONS(201),
    [anon_sym_false] = ACTIONS(201),
    [anon_sym_not] = ACTIONS(201),
    [anon_sym_BANG] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(201),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(201),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(203),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(201),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(201),
    [anon_sym_icmp_DOTtype] = ACTIONS(201),
    [anon_sym_icmp_DOTcode] = ACTIONS(201),
    [anon_sym_ip_DOThdr_len] = ACTIONS(201),
    [anon_sym_ip_DOTlen] = ACTIONS(201),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(201),
    [anon_sym_ip_DOTttl] = ACTIONS(201),
    [anon_sym_tcp_DOTflags] = ACTIONS(203),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(201),
    [anon_sym_tcp_DOTdstport] = ACTIONS(201),
    [anon_sym_udp_DOTdstport] = ACTIONS(201),
    [anon_sym_udp_DOTsrcport] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(201),
    [anon_sym_ip_DOTsrc] = ACTIONS(203),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(201),
    [anon_sym_ip_DOTdst] = ACTIONS(203),
    [anon_sym_http_DOTcookie] = ACTIONS(201),
    [anon_sym_http_DOThost] = ACTIONS(201),
    [anon_sym_http_DOTreferer] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(201),
    [anon_sym_http_DOTuser_agent] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(201),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(203),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(201),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(201),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(201),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(201),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(201),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(201),
    [anon_sym_icmp] = ACTIONS(203),
    [anon_sym_ip] = ACTIONS(203),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(201),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(201),
    [anon_sym_tcp] = ACTIONS(203),
    [anon_sym_udp] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(201),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(203),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(203),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(203),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(201),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(201),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(201),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(201),
    [anon_sym_ssl] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(201),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(201),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(201),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(201),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(201),
    [anon_sym_sip] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(201),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(201),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(201),
  },
  [28] = {
    [ts_builtin_sym_end] = ACTIONS(205),
    [anon_sym_AMP_AMP] = ACTIONS(205),
    [anon_sym_and] = ACTIONS(205),
    [anon_sym_xor] = ACTIONS(205),
    [anon_sym_CARET_CARET] = ACTIONS(205),
    [anon_sym_or] = ACTIONS(205),
    [anon_sym_PIPE_PIPE] = ACTIONS(205),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(205),
    [anon_sym_LPAREN] = ACTIONS(205),
    [anon_sym_RPAREN] = ACTIONS(205),
    [anon_sym_lookup_json_string] = ACTIONS(205),
    [anon_sym_lower] = ACTIONS(205),
    [anon_sym_regex_replace] = ACTIONS(205),
    [anon_sym_remove_bytes] = ACTIONS(205),
    [anon_sym_to_string] = ACTIONS(205),
    [anon_sym_upper] = ACTIONS(205),
    [anon_sym_url_decode] = ACTIONS(205),
    [anon_sym_uuidv4] = ACTIONS(205),
    [anon_sym_len] = ACTIONS(205),
    [anon_sym_ends_with] = ACTIONS(205),
    [anon_sym_starts_with] = ACTIONS(205),
    [anon_sym_any] = ACTIONS(205),
    [anon_sym_all] = ACTIONS(205),
    [anon_sym_true] = ACTIONS(205),
    [anon_sym_false] = ACTIONS(205),
    [anon_sym_not] = ACTIONS(205),
    [anon_sym_BANG] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(205),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(205),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(207),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(205),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(205),
    [anon_sym_icmp_DOTtype] = ACTIONS(205),
    [anon_sym_icmp_DOTcode] = ACTIONS(205),
    [anon_sym_ip_DOThdr_len] = ACTIONS(205),
    [anon_sym_ip_DOTlen] = ACTIONS(205),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(205),
    [anon_sym_ip_DOTttl] = ACTIONS(205),
    [anon_sym_tcp_DOTflags] = ACTIONS(207),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(205),
    [anon_sym_tcp_DOTdstport] = ACTIONS(205),
    [anon_sym_udp_DOTdstport] = ACTIONS(205),
    [anon_sym_udp_DOTsrcport] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(205),
    [anon_sym_ip_DOTsrc] = ACTIONS(207),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(205),
    [anon_sym_ip_DOTdst] = ACTIONS(207),
    [anon_sym_http_DOTcookie] = ACTIONS(205),
    [anon_sym_http_DOThost] = ACTIONS(205),
    [anon_sym_http_DOTreferer] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(205),
    [anon_sym_http_DOTuser_agent] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(205),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(207),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(207),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(205),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(205),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(205),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(205),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(205),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(205),
    [anon_sym_icmp] = ACTIONS(207),
    [anon_sym_ip] = ACTIONS(207),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(205),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(205),
    [anon_sym_tcp] = ACTIONS(207),
    [anon_sym_udp] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(205),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(207),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(207),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(207),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(205),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(205),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(205),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(205),
    [anon_sym_ssl] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(205),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(205),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(205),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(205),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(205),
    [anon_sym_sip] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(205),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(205),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(205),
  },
  [29] = {
    [ts_builtin_sym_end] = ACTIONS(209),
    [anon_sym_AMP_AMP] = ACTIONS(143),
    [anon_sym_and] = ACTIONS(143),
    [anon_sym_xor] = ACTIONS(145),
    [anon_sym_CARET_CARET] = ACTIONS(145),
    [anon_sym_or] = ACTIONS(211),
    [anon_sym_PIPE_PIPE] = ACTIONS(211),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(209),
    [anon_sym_LPAREN] = ACTIONS(209),
    [anon_sym_lookup_json_string] = ACTIONS(209),
    [anon_sym_lower] = ACTIONS(209),
    [anon_sym_regex_replace] = ACTIONS(209),
    [anon_sym_remove_bytes] = ACTIONS(209),
    [anon_sym_to_string] = ACTIONS(209),
    [anon_sym_upper] = ACTIONS(209),
    [anon_sym_url_decode] = ACTIONS(209),
    [anon_sym_uuidv4] = ACTIONS(209),
    [anon_sym_len] = ACTIONS(209),
    [anon_sym_ends_with] = ACTIONS(209),
    [anon_sym_starts_with] = ACTIONS(209),
    [anon_sym_any] = ACTIONS(209),
    [anon_sym_all] = ACTIONS(209),
    [anon_sym_true] = ACTIONS(209),
    [anon_sym_false] = ACTIONS(209),
    [anon_sym_not] = ACTIONS(209),
    [anon_sym_BANG] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(209),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(209),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(213),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(209),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(209),
    [anon_sym_icmp_DOTtype] = ACTIONS(209),
    [anon_sym_icmp_DOTcode] = ACTIONS(209),
    [anon_sym_ip_DOThdr_len] = ACTIONS(209),
    [anon_sym_ip_DOTlen] = ACTIONS(209),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(209),
    [anon_sym_ip_DOTttl] = ACTIONS(209),
    [anon_sym_tcp_DOTflags] = ACTIONS(213),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(209),
    [anon_sym_tcp_DOTdstport] = ACTIONS(209),
    [anon_sym_udp_DOTdstport] = ACTIONS(209),
    [anon_sym_udp_DOTsrcport] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(209),
    [anon_sym_ip_DOTsrc] = ACTIONS(213),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(209),
    [anon_sym_ip_DOTdst] = ACTIONS(213),
    [anon_sym_http_DOTcookie] = ACTIONS(209),
    [anon_sym_http_DOThost] = ACTIONS(209),
    [anon_sym_http_DOTreferer] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(209),
    [anon_sym_http_DOTuser_agent] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(209),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(213),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(209),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(209),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(209),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(209),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(209),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(209),
    [anon_sym_icmp] = ACTIONS(213),
    [anon_sym_ip] = ACTIONS(213),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(209),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(209),
    [anon_sym_tcp] = ACTIONS(213),
    [anon_sym_udp] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(209),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(213),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(213),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(213),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(209),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(209),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(209),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(209),
    [anon_sym_ssl] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(209),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(209),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(209),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(209),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(209),
    [anon_sym_sip] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(209),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(209),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(209),
  },
  [30] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(215),
    [anon_sym_LPAREN] = ACTIONS(215),
    [anon_sym_lookup_json_string] = ACTIONS(215),
    [anon_sym_lower] = ACTIONS(215),
    [anon_sym_regex_replace] = ACTIONS(215),
    [anon_sym_remove_bytes] = ACTIONS(215),
    [anon_sym_to_string] = ACTIONS(215),
    [anon_sym_upper] = ACTIONS(215),
    [anon_sym_url_decode] = ACTIONS(215),
    [anon_sym_uuidv4] = ACTIONS(215),
    [anon_sym_len] = ACTIONS(215),
    [anon_sym_ends_with] = ACTIONS(215),
    [anon_sym_starts_with] = ACTIONS(215),
    [anon_sym_any] = ACTIONS(215),
    [anon_sym_all] = ACTIONS(215),
    [anon_sym_true] = ACTIONS(215),
    [anon_sym_false] = ACTIONS(215),
    [anon_sym_not] = ACTIONS(215),
    [anon_sym_BANG] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTsec] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTasnum] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTscore] = ACTIONS(215),
    [anon_sym_cf_DOTedge_DOTserver_port] = ACTIONS(215),
    [anon_sym_cf_DOTthreat_score] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore] = ACTIONS(217),
    [anon_sym_cf_DOTwaf_DOTscore_DOTsqli] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore_DOTxss] = ACTIONS(215),
    [anon_sym_cf_DOTwaf_DOTscore_DOTrce] = ACTIONS(215),
    [anon_sym_icmp_DOTtype] = ACTIONS(215),
    [anon_sym_icmp_DOTcode] = ACTIONS(215),
    [anon_sym_ip_DOThdr_len] = ACTIONS(215),
    [anon_sym_ip_DOTlen] = ACTIONS(215),
    [anon_sym_ip_DOTopt_DOTtype] = ACTIONS(215),
    [anon_sym_ip_DOTttl] = ACTIONS(215),
    [anon_sym_tcp_DOTflags] = ACTIONS(217),
    [anon_sym_tcp_DOTsrcport] = ACTIONS(215),
    [anon_sym_tcp_DOTdstport] = ACTIONS(215),
    [anon_sym_udp_DOTdstport] = ACTIONS(215),
    [anon_sym_udp_DOTsrcport] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTsize] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOTcode] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOT1xxx_code] = ACTIONS(215),
    [anon_sym_ip_DOTsrc] = ACTIONS(217),
    [anon_sym_cf_DOTedge_DOTserver_ip] = ACTIONS(215),
    [anon_sym_ip_DOTdst] = ACTIONS(217),
    [anon_sym_http_DOTcookie] = ACTIONS(215),
    [anon_sym_http_DOThost] = ACTIONS(215),
    [anon_sym_http_DOTreferer] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(215),
    [anon_sym_http_DOTuser_agent] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(215),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(217),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(215),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(215),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(215),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(215),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(215),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(215),
    [anon_sym_icmp] = ACTIONS(217),
    [anon_sym_ip] = ACTIONS(217),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(215),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(215),
    [anon_sym_tcp] = ACTIONS(217),
    [anon_sym_udp] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(215),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(217),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(217),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(217),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(215),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(215),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTdetection_ids] = ACTIONS(215),
    [anon_sym_ip_DOTgeoip_DOTis_in_european_union] = ACTIONS(215),
    [anon_sym_ssl] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTverified_bot] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTcorporate_proxy] = ACTIONS(215),
    [anon_sym_cf_DOTbot_management_DOTstatic_resource] = ACTIONS(215),
    [anon_sym_cf_DOTclient_DOTbot] = ACTIONS(215),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_revoked] = ACTIONS(215),
    [anon_sym_cf_DOTtls_client_auth_DOTcert_verified] = ACTIONS(215),
    [anon_sym_sip] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTack] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTcwr] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTecn] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTfin] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTpush] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTreset] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTsyn] = ACTIONS(215),
    [anon_sym_tcp_DOTflags_DOTurg] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTheaders_DOTtruncated] = ACTIONS(215),
    [anon_sym_http_DOTrequest_DOTbody_DOTtruncated] = ACTIONS(215),
  },
  [31] = {
    [anon_sym_in] = ACTIONS(219),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(219),
    [anon_sym_ne] = ACTIONS(219),
    [anon_sym_lt] = ACTIONS(219),
    [anon_sym_le] = ACTIONS(219),
    [anon_sym_gt] = ACTIONS(219),
    [anon_sym_ge] = ACTIONS(219),
    [anon_sym_EQ_EQ] = ACTIONS(219),
    [anon_sym_BANG_EQ] = ACTIONS(219),
    [anon_sym_LT] = ACTIONS(221),
    [anon_sym_LT_EQ] = ACTIONS(219),
    [anon_sym_GT] = ACTIONS(221),
    [anon_sym_GT_EQ] = ACTIONS(219),
    [anon_sym_contains] = ACTIONS(219),
    [anon_sym_matches] = ACTIONS(219),
    [anon_sym_TILDE] = ACTIONS(219),
    [anon_sym_concat] = ACTIONS(219),
    [anon_sym_COMMA] = ACTIONS(219),
    [anon_sym_RPAREN] = ACTIONS(219),
    [anon_sym_lookup_json_string] = ACTIONS(219),
    [anon_sym_lower] = ACTIONS(219),
    [anon_sym_regex_replace] = ACTIONS(219),
    [anon_sym_remove_bytes] = ACTIONS(219),
    [anon_sym_to_string] = ACTIONS(219),
    [anon_sym_upper] = ACTIONS(219),
    [anon_sym_url_decode] = ACTIONS(219),
    [anon_sym_uuidv4] = ACTIONS(219),
    [sym_number] = ACTIONS(219),
    [sym_string] = ACTIONS(219),
    [anon_sym_http_DOTcookie] = ACTIONS(219),
    [anon_sym_http_DOThost] = ACTIONS(219),
    [anon_sym_http_DOTreferer] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(219),
    [anon_sym_http_DOTuser_agent] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(219),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(221),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(219),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(219),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(219),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(219),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(219),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(219),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(219),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(219),
    [anon_sym_icmp] = ACTIONS(219),
    [anon_sym_ip] = ACTIONS(221),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(219),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(219),
    [anon_sym_tcp] = ACTIONS(219),
    [anon_sym_udp] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(219),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(221),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(221),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(221),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(219),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(219),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(219),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(219),
  },
  [32] = {
    [anon_sym_in] = ACTIONS(223),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(223),
    [anon_sym_ne] = ACTIONS(223),
    [anon_sym_lt] = ACTIONS(223),
    [anon_sym_le] = ACTIONS(223),
    [anon_sym_gt] = ACTIONS(223),
    [anon_sym_ge] = ACTIONS(223),
    [anon_sym_EQ_EQ] = ACTIONS(223),
    [anon_sym_BANG_EQ] = ACTIONS(223),
    [anon_sym_LT] = ACTIONS(225),
    [anon_sym_LT_EQ] = ACTIONS(223),
    [anon_sym_GT] = ACTIONS(225),
    [anon_sym_GT_EQ] = ACTIONS(223),
    [anon_sym_contains] = ACTIONS(223),
    [anon_sym_matches] = ACTIONS(223),
    [anon_sym_TILDE] = ACTIONS(223),
    [anon_sym_concat] = ACTIONS(223),
    [anon_sym_COMMA] = ACTIONS(223),
    [anon_sym_RPAREN] = ACTIONS(223),
    [anon_sym_lookup_json_string] = ACTIONS(223),
    [anon_sym_lower] = ACTIONS(223),
    [anon_sym_regex_replace] = ACTIONS(223),
    [anon_sym_remove_bytes] = ACTIONS(223),
    [anon_sym_to_string] = ACTIONS(223),
    [anon_sym_upper] = ACTIONS(223),
    [anon_sym_url_decode] = ACTIONS(223),
    [anon_sym_uuidv4] = ACTIONS(223),
    [sym_number] = ACTIONS(223),
    [sym_string] = ACTIONS(223),
    [anon_sym_http_DOTcookie] = ACTIONS(223),
    [anon_sym_http_DOThost] = ACTIONS(223),
    [anon_sym_http_DOTreferer] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(223),
    [anon_sym_http_DOTuser_agent] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(223),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(225),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(223),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(223),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(223),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(223),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(223),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(223),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(223),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(223),
    [anon_sym_icmp] = ACTIONS(223),
    [anon_sym_ip] = ACTIONS(225),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(223),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(223),
    [anon_sym_tcp] = ACTIONS(223),
    [anon_sym_udp] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(223),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(225),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(225),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(225),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(223),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(223),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(223),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(223),
  },
  [33] = {
    [anon_sym_in] = ACTIONS(227),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(227),
    [anon_sym_ne] = ACTIONS(227),
    [anon_sym_lt] = ACTIONS(227),
    [anon_sym_le] = ACTIONS(227),
    [anon_sym_gt] = ACTIONS(227),
    [anon_sym_ge] = ACTIONS(227),
    [anon_sym_EQ_EQ] = ACTIONS(227),
    [anon_sym_BANG_EQ] = ACTIONS(227),
    [anon_sym_LT] = ACTIONS(229),
    [anon_sym_LT_EQ] = ACTIONS(227),
    [anon_sym_GT] = ACTIONS(229),
    [anon_sym_GT_EQ] = ACTIONS(227),
    [anon_sym_contains] = ACTIONS(227),
    [anon_sym_matches] = ACTIONS(227),
    [anon_sym_TILDE] = ACTIONS(227),
    [anon_sym_concat] = ACTIONS(227),
    [anon_sym_COMMA] = ACTIONS(227),
    [anon_sym_RPAREN] = ACTIONS(227),
    [anon_sym_lookup_json_string] = ACTIONS(227),
    [anon_sym_lower] = ACTIONS(227),
    [anon_sym_regex_replace] = ACTIONS(227),
    [anon_sym_remove_bytes] = ACTIONS(227),
    [anon_sym_to_string] = ACTIONS(227),
    [anon_sym_upper] = ACTIONS(227),
    [anon_sym_url_decode] = ACTIONS(227),
    [anon_sym_uuidv4] = ACTIONS(227),
    [sym_number] = ACTIONS(227),
    [sym_string] = ACTIONS(227),
    [anon_sym_http_DOTcookie] = ACTIONS(227),
    [anon_sym_http_DOThost] = ACTIONS(227),
    [anon_sym_http_DOTreferer] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(227),
    [anon_sym_http_DOTuser_agent] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(227),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(229),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(227),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(229),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(227),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(227),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(227),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(227),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(227),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(227),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(227),
    [anon_sym_icmp] = ACTIONS(227),
    [anon_sym_ip] = ACTIONS(229),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(227),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(227),
    [anon_sym_tcp] = ACTIONS(227),
    [anon_sym_udp] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(227),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(229),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(229),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(229),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(227),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(227),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(227),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(227),
  },
  [34] = {
    [anon_sym_in] = ACTIONS(231),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(231),
    [anon_sym_ne] = ACTIONS(231),
    [anon_sym_lt] = ACTIONS(231),
    [anon_sym_le] = ACTIONS(231),
    [anon_sym_gt] = ACTIONS(231),
    [anon_sym_ge] = ACTIONS(231),
    [anon_sym_EQ_EQ] = ACTIONS(231),
    [anon_sym_BANG_EQ] = ACTIONS(231),
    [anon_sym_LT] = ACTIONS(233),
    [anon_sym_LT_EQ] = ACTIONS(231),
    [anon_sym_GT] = ACTIONS(233),
    [anon_sym_GT_EQ] = ACTIONS(231),
    [anon_sym_contains] = ACTIONS(231),
    [anon_sym_matches] = ACTIONS(231),
    [anon_sym_TILDE] = ACTIONS(231),
    [anon_sym_concat] = ACTIONS(231),
    [anon_sym_COMMA] = ACTIONS(231),
    [anon_sym_RPAREN] = ACTIONS(231),
    [anon_sym_lookup_json_string] = ACTIONS(231),
    [anon_sym_lower] = ACTIONS(231),
    [anon_sym_regex_replace] = ACTIONS(231),
    [anon_sym_remove_bytes] = ACTIONS(231),
    [anon_sym_to_string] = ACTIONS(231),
    [anon_sym_upper] = ACTIONS(231),
    [anon_sym_url_decode] = ACTIONS(231),
    [anon_sym_uuidv4] = ACTIONS(231),
    [sym_number] = ACTIONS(231),
    [sym_string] = ACTIONS(231),
    [anon_sym_http_DOTcookie] = ACTIONS(231),
    [anon_sym_http_DOThost] = ACTIONS(231),
    [anon_sym_http_DOTreferer] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(231),
    [anon_sym_http_DOTuser_agent] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(231),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(233),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(231),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(231),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(231),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(231),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(231),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(231),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(233),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(231),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(231),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(231),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(231),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(231),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(231),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(231),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(231),
    [anon_sym_icmp] = ACTIONS(231),
    [anon_sym_ip] = ACTIONS(233),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(231),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(231),
    [anon_sym_tcp] = ACTIONS(231),
    [anon_sym_udp] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(231),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(233),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(233),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(233),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(231),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(231),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(231),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(231),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(231),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(231),
  },
  [35] = {
    [anon_sym_in] = ACTIONS(235),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(235),
    [anon_sym_ne] = ACTIONS(235),
    [anon_sym_lt] = ACTIONS(235),
    [anon_sym_le] = ACTIONS(235),
    [anon_sym_gt] = ACTIONS(235),
    [anon_sym_ge] = ACTIONS(235),
    [anon_sym_EQ_EQ] = ACTIONS(235),
    [anon_sym_BANG_EQ] = ACTIONS(235),
    [anon_sym_LT] = ACTIONS(237),
    [anon_sym_LT_EQ] = ACTIONS(235),
    [anon_sym_GT] = ACTIONS(237),
    [anon_sym_GT_EQ] = ACTIONS(235),
    [anon_sym_contains] = ACTIONS(235),
    [anon_sym_matches] = ACTIONS(235),
    [anon_sym_TILDE] = ACTIONS(235),
    [anon_sym_concat] = ACTIONS(235),
    [anon_sym_COMMA] = ACTIONS(235),
    [anon_sym_RPAREN] = ACTIONS(235),
    [anon_sym_lookup_json_string] = ACTIONS(235),
    [anon_sym_lower] = ACTIONS(235),
    [anon_sym_regex_replace] = ACTIONS(235),
    [anon_sym_remove_bytes] = ACTIONS(235),
    [anon_sym_to_string] = ACTIONS(235),
    [anon_sym_upper] = ACTIONS(235),
    [anon_sym_url_decode] = ACTIONS(235),
    [anon_sym_uuidv4] = ACTIONS(235),
    [sym_number] = ACTIONS(235),
    [sym_string] = ACTIONS(235),
    [anon_sym_http_DOTcookie] = ACTIONS(235),
    [anon_sym_http_DOThost] = ACTIONS(235),
    [anon_sym_http_DOTreferer] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(235),
    [anon_sym_http_DOTuser_agent] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(235),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(237),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(235),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(235),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(235),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(235),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(235),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(235),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(237),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(235),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(235),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(235),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(235),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(235),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(235),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(235),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(235),
    [anon_sym_icmp] = ACTIONS(235),
    [anon_sym_ip] = ACTIONS(237),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(235),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(235),
    [anon_sym_tcp] = ACTIONS(235),
    [anon_sym_udp] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(235),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(237),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(237),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(237),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(235),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(235),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(235),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(235),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(235),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(235),
  },
  [36] = {
    [anon_sym_in] = ACTIONS(239),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(239),
    [anon_sym_ne] = ACTIONS(239),
    [anon_sym_lt] = ACTIONS(239),
    [anon_sym_le] = ACTIONS(239),
    [anon_sym_gt] = ACTIONS(239),
    [anon_sym_ge] = ACTIONS(239),
    [anon_sym_EQ_EQ] = ACTIONS(239),
    [anon_sym_BANG_EQ] = ACTIONS(239),
    [anon_sym_LT] = ACTIONS(241),
    [anon_sym_LT_EQ] = ACTIONS(239),
    [anon_sym_GT] = ACTIONS(241),
    [anon_sym_GT_EQ] = ACTIONS(239),
    [anon_sym_contains] = ACTIONS(239),
    [anon_sym_matches] = ACTIONS(239),
    [anon_sym_TILDE] = ACTIONS(239),
    [anon_sym_concat] = ACTIONS(239),
    [anon_sym_COMMA] = ACTIONS(239),
    [anon_sym_RPAREN] = ACTIONS(239),
    [anon_sym_lookup_json_string] = ACTIONS(239),
    [anon_sym_lower] = ACTIONS(239),
    [anon_sym_regex_replace] = ACTIONS(239),
    [anon_sym_remove_bytes] = ACTIONS(239),
    [anon_sym_to_string] = ACTIONS(239),
    [anon_sym_upper] = ACTIONS(239),
    [anon_sym_url_decode] = ACTIONS(239),
    [anon_sym_uuidv4] = ACTIONS(239),
    [sym_number] = ACTIONS(239),
    [sym_string] = ACTIONS(239),
    [anon_sym_http_DOTcookie] = ACTIONS(239),
    [anon_sym_http_DOThost] = ACTIONS(239),
    [anon_sym_http_DOTreferer] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(239),
    [anon_sym_http_DOTuser_agent] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(239),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(241),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(239),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(239),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(239),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(239),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(239),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(239),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(241),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(239),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(239),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(239),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(239),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(239),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(239),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(239),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(239),
    [anon_sym_icmp] = ACTIONS(239),
    [anon_sym_ip] = ACTIONS(241),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(239),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(239),
    [anon_sym_tcp] = ACTIONS(239),
    [anon_sym_udp] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(239),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(241),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(241),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(241),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(239),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(239),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(239),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(239),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(239),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(239),
  },
  [37] = {
    [anon_sym_in] = ACTIONS(243),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(243),
    [anon_sym_ne] = ACTIONS(243),
    [anon_sym_lt] = ACTIONS(243),
    [anon_sym_le] = ACTIONS(243),
    [anon_sym_gt] = ACTIONS(243),
    [anon_sym_ge] = ACTIONS(243),
    [anon_sym_EQ_EQ] = ACTIONS(243),
    [anon_sym_BANG_EQ] = ACTIONS(243),
    [anon_sym_LT] = ACTIONS(245),
    [anon_sym_LT_EQ] = ACTIONS(243),
    [anon_sym_GT] = ACTIONS(245),
    [anon_sym_GT_EQ] = ACTIONS(243),
    [anon_sym_contains] = ACTIONS(243),
    [anon_sym_matches] = ACTIONS(243),
    [anon_sym_TILDE] = ACTIONS(243),
    [anon_sym_concat] = ACTIONS(243),
    [anon_sym_COMMA] = ACTIONS(243),
    [anon_sym_RPAREN] = ACTIONS(243),
    [anon_sym_lookup_json_string] = ACTIONS(243),
    [anon_sym_lower] = ACTIONS(243),
    [anon_sym_regex_replace] = ACTIONS(243),
    [anon_sym_remove_bytes] = ACTIONS(243),
    [anon_sym_to_string] = ACTIONS(243),
    [anon_sym_upper] = ACTIONS(243),
    [anon_sym_url_decode] = ACTIONS(243),
    [anon_sym_uuidv4] = ACTIONS(243),
    [sym_number] = ACTIONS(243),
    [sym_string] = ACTIONS(243),
    [anon_sym_http_DOTcookie] = ACTIONS(243),
    [anon_sym_http_DOThost] = ACTIONS(243),
    [anon_sym_http_DOTreferer] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(245),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(245),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(243),
    [anon_sym_http_DOTuser_agent] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(243),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(245),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(243),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(243),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(243),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(243),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(243),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(243),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(245),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(243),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(243),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(243),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(243),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(243),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(243),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(243),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(243),
    [anon_sym_icmp] = ACTIONS(243),
    [anon_sym_ip] = ACTIONS(245),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(243),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(243),
    [anon_sym_tcp] = ACTIONS(243),
    [anon_sym_udp] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(243),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(245),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(245),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(245),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(245),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(245),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(243),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(243),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(243),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(243),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(243),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(243),
  },
  [38] = {
    [anon_sym_in] = ACTIONS(247),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(247),
    [anon_sym_ne] = ACTIONS(247),
    [anon_sym_lt] = ACTIONS(247),
    [anon_sym_le] = ACTIONS(247),
    [anon_sym_gt] = ACTIONS(247),
    [anon_sym_ge] = ACTIONS(247),
    [anon_sym_EQ_EQ] = ACTIONS(247),
    [anon_sym_BANG_EQ] = ACTIONS(247),
    [anon_sym_LT] = ACTIONS(249),
    [anon_sym_LT_EQ] = ACTIONS(247),
    [anon_sym_GT] = ACTIONS(249),
    [anon_sym_GT_EQ] = ACTIONS(247),
    [anon_sym_contains] = ACTIONS(247),
    [anon_sym_matches] = ACTIONS(247),
    [anon_sym_TILDE] = ACTIONS(247),
    [anon_sym_concat] = ACTIONS(247),
    [anon_sym_COMMA] = ACTIONS(247),
    [anon_sym_RPAREN] = ACTIONS(247),
    [anon_sym_lookup_json_string] = ACTIONS(247),
    [anon_sym_lower] = ACTIONS(247),
    [anon_sym_regex_replace] = ACTIONS(247),
    [anon_sym_remove_bytes] = ACTIONS(247),
    [anon_sym_to_string] = ACTIONS(247),
    [anon_sym_upper] = ACTIONS(247),
    [anon_sym_url_decode] = ACTIONS(247),
    [anon_sym_uuidv4] = ACTIONS(247),
    [sym_number] = ACTIONS(247),
    [sym_string] = ACTIONS(247),
    [anon_sym_http_DOTcookie] = ACTIONS(247),
    [anon_sym_http_DOThost] = ACTIONS(247),
    [anon_sym_http_DOTreferer] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(249),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(249),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(247),
    [anon_sym_http_DOTuser_agent] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(247),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(249),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(247),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(247),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(247),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(247),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(247),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(247),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(249),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(247),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(247),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(247),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(247),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(247),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(247),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(247),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(247),
    [anon_sym_icmp] = ACTIONS(247),
    [anon_sym_ip] = ACTIONS(249),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(247),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(247),
    [anon_sym_tcp] = ACTIONS(247),
    [anon_sym_udp] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(247),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(249),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(249),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(249),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(249),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(249),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(247),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(247),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(247),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(247),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(247),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(247),
  },
  [39] = {
    [anon_sym_in] = ACTIONS(251),
    [sym_comment] = ACTIONS(3),
    [anon_sym_eq] = ACTIONS(251),
    [anon_sym_ne] = ACTIONS(251),
    [anon_sym_lt] = ACTIONS(251),
    [anon_sym_le] = ACTIONS(251),
    [anon_sym_gt] = ACTIONS(251),
    [anon_sym_ge] = ACTIONS(251),
    [anon_sym_EQ_EQ] = ACTIONS(251),
    [anon_sym_BANG_EQ] = ACTIONS(251),
    [anon_sym_LT] = ACTIONS(253),
    [anon_sym_LT_EQ] = ACTIONS(251),
    [anon_sym_GT] = ACTIONS(253),
    [anon_sym_GT_EQ] = ACTIONS(251),
    [anon_sym_contains] = ACTIONS(251),
    [anon_sym_matches] = ACTIONS(251),
    [anon_sym_TILDE] = ACTIONS(251),
    [anon_sym_concat] = ACTIONS(251),
    [anon_sym_COMMA] = ACTIONS(251),
    [anon_sym_RPAREN] = ACTIONS(251),
    [anon_sym_lookup_json_string] = ACTIONS(251),
    [anon_sym_lower] = ACTIONS(251),
    [anon_sym_regex_replace] = ACTIONS(251),
    [anon_sym_remove_bytes] = ACTIONS(251),
    [anon_sym_to_string] = ACTIONS(251),
    [anon_sym_upper] = ACTIONS(251),
    [anon_sym_url_decode] = ACTIONS(251),
    [anon_sym_uuidv4] = ACTIONS(251),
    [sym_number] = ACTIONS(251),
    [sym_string] = ACTIONS(251),
    [anon_sym_http_DOTcookie] = ACTIONS(251),
    [anon_sym_http_DOThost] = ACTIONS(251),
    [anon_sym_http_DOTreferer] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(253),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(253),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(251),
    [anon_sym_http_DOTuser_agent] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(251),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(253),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(251),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(251),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(251),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(251),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(251),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(251),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(253),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(251),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(251),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(251),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(251),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(251),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(251),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(251),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(251),
    [anon_sym_icmp] = ACTIONS(251),
    [anon_sym_ip] = ACTIONS(253),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(251),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(251),
    [anon_sym_tcp] = ACTIONS(251),
    [anon_sym_udp] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(251),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(253),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(253),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(253),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(253),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(253),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(251),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(251),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(251),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(251),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(251),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(251),
  },
  [40] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(211),
    [sym_stringlike_field] = STATE(62),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [aux_sym_string_func_repeat1] = STATE(41),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_RPAREN] = ACTIONS(255),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [sym_string] = ACTIONS(257),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [41] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(211),
    [sym_stringlike_field] = STATE(62),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [aux_sym_string_func_repeat1] = STATE(41),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(259),
    [anon_sym_RPAREN] = ACTIONS(262),
    [anon_sym_lookup_json_string] = ACTIONS(264),
    [anon_sym_lower] = ACTIONS(267),
    [anon_sym_regex_replace] = ACTIONS(270),
    [anon_sym_remove_bytes] = ACTIONS(273),
    [anon_sym_to_string] = ACTIONS(276),
    [anon_sym_upper] = ACTIONS(267),
    [anon_sym_url_decode] = ACTIONS(267),
    [anon_sym_uuidv4] = ACTIONS(279),
    [sym_string] = ACTIONS(282),
    [anon_sym_http_DOTcookie] = ACTIONS(285),
    [anon_sym_http_DOThost] = ACTIONS(285),
    [anon_sym_http_DOTreferer] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(288),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(288),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(285),
    [anon_sym_http_DOTuser_agent] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(285),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(288),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(285),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(285),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(285),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(285),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(285),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(285),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(288),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(285),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(285),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(285),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(285),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(285),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(285),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(285),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(285),
    [anon_sym_icmp] = ACTIONS(285),
    [anon_sym_ip] = ACTIONS(288),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(285),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(285),
    [anon_sym_tcp] = ACTIONS(285),
    [anon_sym_udp] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(285),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(285),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(291),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(294),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(294),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(294),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(294),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(294),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(297),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(297),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(297),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(297),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(297),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(297),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(297),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(297),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(297),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(297),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(297),
  },
  [42] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(211),
    [sym_stringlike_field] = STATE(62),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [aux_sym_string_func_repeat1] = STATE(41),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_RPAREN] = ACTIONS(300),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [sym_string] = ACTIONS(257),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [43] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(189),
    [sym_stringlike_field] = STATE(183),
    [sym_string_field] = STATE(33),
    [sym_bytes_field] = STATE(183),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(316),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [44] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(239),
    [sym_stringlike_field] = STATE(183),
    [sym_string_field] = STATE(33),
    [sym_bytes_field] = STATE(183),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(316),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [45] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(211),
    [sym_stringlike_field] = STATE(62),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [aux_sym_string_func_repeat1] = STATE(41),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_RPAREN] = ACTIONS(320),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [sym_string] = ACTIONS(257),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [46] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(179),
    [sym_stringlike_field] = STATE(178),
    [sym_string_field] = STATE(33),
    [sym_bytes_field] = STATE(178),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_cf_DOTrandom_seed] = ACTIONS(316),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [47] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(238),
    [sym_stringlike_field] = STATE(201),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [sym_string] = ACTIONS(322),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [48] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(211),
    [sym_stringlike_field] = STATE(62),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [aux_sym_string_func_repeat1] = STATE(45),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [sym_string] = ACTIONS(257),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [49] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(211),
    [sym_stringlike_field] = STATE(62),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [aux_sym_string_func_repeat1] = STATE(40),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [sym_string] = ACTIONS(257),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [50] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(200),
    [sym_stringlike_field] = STATE(201),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [sym_string] = ACTIONS(322),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [51] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(211),
    [sym_stringlike_field] = STATE(62),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(210),
    [sym_array_string_field] = STATE(209),
    [aux_sym_string_func_repeat1] = STATE(42),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(7),
    [anon_sym_lookup_json_string] = ACTIONS(11),
    [anon_sym_lower] = ACTIONS(13),
    [anon_sym_regex_replace] = ACTIONS(15),
    [anon_sym_remove_bytes] = ACTIONS(17),
    [anon_sym_to_string] = ACTIONS(19),
    [anon_sym_upper] = ACTIONS(13),
    [anon_sym_url_decode] = ACTIONS(13),
    [anon_sym_uuidv4] = ACTIONS(21),
    [sym_string] = ACTIONS(257),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(49),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(49),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(49),
  },
  [52] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(102),
    [sym_stringlike_field] = STATE(106),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [53] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(240),
    [sym_stringlike_field] = STATE(176),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [54] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(104),
    [sym_stringlike_field] = STATE(106),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [55] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(193),
    [sym_stringlike_field] = STATE(191),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [56] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(214),
    [sym_stringlike_field] = STATE(180),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [57] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(251),
    [sym_stringlike_field] = STATE(191),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [58] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(213),
    [sym_stringlike_field] = STATE(196),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [59] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(198),
    [sym_stringlike_field] = STATE(196),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [60] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(181),
    [sym_stringlike_field] = STATE(180),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [61] = {
    [sym_string_func] = STATE(33),
    [sym_string_array] = STATE(128),
    [sym__string_array_expansion] = STATE(177),
    [sym_stringlike_field] = STATE(176),
    [sym_string_field] = STATE(33),
    [sym_map_string_array_field] = STATE(199),
    [sym_array_string_field] = STATE(122),
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(302),
    [anon_sym_lookup_json_string] = ACTIONS(304),
    [anon_sym_lower] = ACTIONS(306),
    [anon_sym_regex_replace] = ACTIONS(308),
    [anon_sym_remove_bytes] = ACTIONS(310),
    [anon_sym_to_string] = ACTIONS(312),
    [anon_sym_upper] = ACTIONS(306),
    [anon_sym_url_decode] = ACTIONS(306),
    [anon_sym_uuidv4] = ACTIONS(314),
    [anon_sym_http_DOTcookie] = ACTIONS(41),
    [anon_sym_http_DOThost] = ACTIONS(41),
    [anon_sym_http_DOTreferer] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(43),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_http_DOTuser_agent] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(41),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(43),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(41),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(43),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(41),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(41),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(41),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(41),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(41),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(41),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(41),
    [anon_sym_icmp] = ACTIONS(41),
    [anon_sym_ip] = ACTIONS(43),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(41),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(41),
    [anon_sym_tcp] = ACTIONS(41),
    [anon_sym_udp] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(41),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(41),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(45),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(47),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(47),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(318),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(318),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(318),
  },
  [62] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(324),
    [anon_sym_COMMA] = ACTIONS(326),
    [anon_sym_RPAREN] = ACTIONS(324),
    [anon_sym_lookup_json_string] = ACTIONS(324),
    [anon_sym_lower] = ACTIONS(324),
    [anon_sym_regex_replace] = ACTIONS(324),
    [anon_sym_remove_bytes] = ACTIONS(324),
    [anon_sym_to_string] = ACTIONS(324),
    [anon_sym_upper] = ACTIONS(324),
    [anon_sym_url_decode] = ACTIONS(324),
    [anon_sym_uuidv4] = ACTIONS(324),
    [sym_string] = ACTIONS(324),
    [anon_sym_http_DOTcookie] = ACTIONS(324),
    [anon_sym_http_DOThost] = ACTIONS(324),
    [anon_sym_http_DOTreferer] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(328),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(328),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(324),
    [anon_sym_http_DOTuser_agent] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(324),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(328),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(324),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(324),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(324),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(324),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(324),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(324),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(328),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(324),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(324),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(324),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(324),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(324),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(324),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(324),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(324),
    [anon_sym_icmp] = ACTIONS(324),
    [anon_sym_ip] = ACTIONS(328),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(324),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(324),
    [anon_sym_tcp] = ACTIONS(324),
    [anon_sym_udp] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(324),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(328),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(328),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(328),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(328),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(328),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(324),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(324),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(324),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(324),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(324),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(324),
  },
  [63] = {
    [sym_comment] = ACTIONS(3),
    [anon_sym_concat] = ACTIONS(262),
    [anon_sym_RPAREN] = ACTIONS(262),
    [anon_sym_lookup_json_string] = ACTIONS(262),
    [anon_sym_lower] = ACTIONS(262),
    [anon_sym_regex_replace] = ACTIONS(262),
    [anon_sym_remove_bytes] = ACTIONS(262),
    [anon_sym_to_string] = ACTIONS(262),
    [anon_sym_upper] = ACTIONS(262),
    [anon_sym_url_decode] = ACTIONS(262),
    [anon_sym_uuidv4] = ACTIONS(262),
    [sym_string] = ACTIONS(262),
    [anon_sym_http_DOTcookie] = ACTIONS(262),
    [anon_sym_http_DOThost] = ACTIONS(262),
    [anon_sym_http_DOTreferer] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTfull_uri] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTmethod] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTuri] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTuri_DOTpath_DOTextension] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTuri_DOTquery] = ACTIONS(262),
    [anon_sym_http_DOTuser_agent] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTversion] = ACTIONS(262),
    [anon_sym_http_DOTx_forwarded_for] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTlat] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTlon] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTcity] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTpostal_code] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTmetro_code] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTregion] = ACTIONS(330),
    [anon_sym_ip_DOTsrc_DOTregion_code] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTtimezone_DOTname] = ACTIONS(262),
    [anon_sym_ip_DOTgeoip_DOTcontinent] = ACTIONS(262),
    [anon_sym_ip_DOTgeoip_DOTcountry] = ACTIONS(262),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_1_iso_code] = ACTIONS(262),
    [anon_sym_ip_DOTgeoip_DOTsubdivision_2_iso_code] = ACTIONS(262),
    [anon_sym_raw_DOThttp_DOTrequest_DOTfull_uri] = ACTIONS(262),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri] = ACTIONS(330),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTpath] = ACTIONS(262),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTquery] = ACTIONS(262),
    [anon_sym_cf_DOTbot_management_DOTja3_hash] = ACTIONS(262),
    [anon_sym_cf_DOTverified_bot_category] = ACTIONS(262),
    [anon_sym_cf_DOThostname_DOTmetadata] = ACTIONS(262),
    [anon_sym_cf_DOTworker_DOTupstream_zone] = ACTIONS(262),
    [anon_sym_cf_DOTcolo_DOTname] = ACTIONS(262),
    [anon_sym_cf_DOTcolo_DOTregion] = ACTIONS(262),
    [anon_sym_icmp] = ACTIONS(262),
    [anon_sym_ip] = ACTIONS(330),
    [anon_sym_ip_DOTdst_DOTcountry] = ACTIONS(262),
    [anon_sym_ip_DOTsrc_DOTcountry] = ACTIONS(262),
    [anon_sym_tcp] = ACTIONS(262),
    [anon_sym_udp] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTbody_DOTraw] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTbody_DOTmime] = ACTIONS(262),
    [anon_sym_cf_DOTresponse_DOTerror_type] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTcookies] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs] = ACTIONS(330),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTheaders] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTbody_DOTform] = ACTIONS(330),
    [anon_sym_http_DOTresponse_DOTheaders] = ACTIONS(330),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(262),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames] = ACTIONS(262),
    [anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTheaders_DOTnames] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTheaders_DOTvalues] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTaccepted_languages] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames] = ACTIONS(262),
    [anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues] = ACTIONS(262),
    [anon_sym_http_DOTresponse_DOTheaders_DOTnames] = ACTIONS(262),
    [anon_sym_http_DOTresponse_DOTheaders_DOTvalues] = ACTIONS(262),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 16,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(332), 1,
      anon_sym_len,
    ACTIONS(336), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(25), 1,
      sym_array_func,
    STATE(77), 1,
      sym_number_field,
    STATE(111), 1,
      sym_number_array,
    STATE(121), 1,
      sym_array_number_field,
    STATE(132), 1,
      sym_bool_array,
    ACTIONS(27), 2,
      anon_sym_any,
      anon_sym_all,
    ACTIONS(35), 2,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_tcp_DOTflags,
    ACTIONS(334), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(24), 2,
      sym_bool_func,
      sym_bool_field,
    ACTIONS(39), 3,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
      anon_sym_ip_DOTdst,
    STATE(196), 3,
      sym_boollike_field,
      sym_numberlike_field,
      sym_ip_field,
    ACTIONS(53), 20,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTbot_management_DOTcorporate_proxy,
      anon_sym_cf_DOTbot_management_DOTstatic_resource,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
      anon_sym_sip,
      anon_sym_tcp_DOTflags_DOTack,
      anon_sym_tcp_DOTflags_DOTcwr,
      anon_sym_tcp_DOTflags_DOTecn,
      anon_sym_tcp_DOTflags_DOTfin,
      anon_sym_tcp_DOTflags_DOTpush,
      anon_sym_tcp_DOTflags_DOTreset,
      anon_sym_tcp_DOTflags_DOTsyn,
      anon_sym_tcp_DOTflags_DOTurg,
      anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
      anon_sym_http_DOTrequest_DOTbody_DOTtruncated,
    ACTIONS(33), 22,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
      anon_sym_ip_DOTgeoip_DOTasnum,
      anon_sym_cf_DOTbot_management_DOTscore,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTthreat_score,
      anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
      anon_sym_cf_DOTwaf_DOTscore_DOTxss,
      anon_sym_cf_DOTwaf_DOTscore_DOTrce,
      anon_sym_icmp_DOTtype,
      anon_sym_icmp_DOTcode,
      anon_sym_ip_DOThdr_len,
      anon_sym_ip_DOTlen,
      anon_sym_ip_DOTopt_DOTtype,
      anon_sym_ip_DOTttl,
      anon_sym_tcp_DOTsrcport,
      anon_sym_tcp_DOTdstport,
      anon_sym_udp_DOTdstport,
      anon_sym_udp_DOTsrcport,
      anon_sym_http_DOTrequest_DOTbody_DOTsize,
      anon_sym_http_DOTresponse_DOTcode,
      anon_sym_http_DOTresponse_DOT1xxx_code,
  [97] = 16,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(332), 1,
      anon_sym_len,
    ACTIONS(336), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(25), 1,
      sym_array_func,
    STATE(77), 1,
      sym_number_field,
    STATE(121), 1,
      sym_array_number_field,
    STATE(131), 1,
      sym_bool_array,
    STATE(133), 1,
      sym_number_array,
    ACTIONS(27), 2,
      anon_sym_any,
      anon_sym_all,
    ACTIONS(35), 2,
      anon_sym_cf_DOTwaf_DOTscore,
      anon_sym_tcp_DOTflags,
    ACTIONS(334), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(24), 2,
      sym_bool_func,
      sym_bool_field,
    ACTIONS(39), 3,
      anon_sym_ip_DOTsrc,
      anon_sym_cf_DOTedge_DOTserver_ip,
      anon_sym_ip_DOTdst,
    STATE(196), 3,
      sym_boollike_field,
      sym_numberlike_field,
      sym_ip_field,
    ACTIONS(53), 20,
      anon_sym_ip_DOTgeoip_DOTis_in_european_union,
      anon_sym_ssl,
      anon_sym_cf_DOTbot_management_DOTverified_bot,
      anon_sym_cf_DOTbot_management_DOTjs_detection_DOTpassed,
      anon_sym_cf_DOTbot_management_DOTcorporate_proxy,
      anon_sym_cf_DOTbot_management_DOTstatic_resource,
      anon_sym_cf_DOTclient_DOTbot,
      anon_sym_cf_DOTtls_client_auth_DOTcert_revoked,
      anon_sym_cf_DOTtls_client_auth_DOTcert_verified,
      anon_sym_sip,
      anon_sym_tcp_DOTflags_DOTack,
      anon_sym_tcp_DOTflags_DOTcwr,
      anon_sym_tcp_DOTflags_DOTecn,
      anon_sym_tcp_DOTflags_DOTfin,
      anon_sym_tcp_DOTflags_DOTpush,
      anon_sym_tcp_DOTflags_DOTreset,
      anon_sym_tcp_DOTflags_DOTsyn,
      anon_sym_tcp_DOTflags_DOTurg,
      anon_sym_http_DOTrequest_DOTheaders_DOTtruncated,
      anon_sym_http_DOTrequest_DOTbody_DOTtruncated,
    ACTIONS(33), 22,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTsec,
      anon_sym_http_DOTrequest_DOTtimestamp_DOTmsec,
      anon_sym_ip_DOTgeoip_DOTasnum,
      anon_sym_cf_DOTbot_management_DOTscore,
      anon_sym_cf_DOTedge_DOTserver_port,
      anon_sym_cf_DOTthreat_score,
      anon_sym_cf_DOTwaf_DOTscore_DOTsqli,
      anon_sym_cf_DOTwaf_DOTscore_DOTxss,
      anon_sym_cf_DOTwaf_DOTscore_DOTrce,
      anon_sym_icmp_DOTtype,
      anon_sym_icmp_DOTcode,
      anon_sym_ip_DOThdr_len,
      anon_sym_ip_DOTlen,
      anon_sym_ip_DOTopt_DOTtype,
      anon_sym_ip_DOTttl,
      anon_sym_tcp_DOTsrcport,
      anon_sym_tcp_DOTdstport,
      anon_sym_udp_DOTdstport,
      anon_sym_udp_DOTsrcport,
      anon_sym_http_DOTrequest_DOTbody_DOTsize,
      anon_sym_http_DOTresponse_DOTcode,
      anon_sym_http_DOTresponse_DOT1xxx_code,
  [194] = 20,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(332), 1,
      anon_sym_len,
    ACTIONS(336), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(121), 1,
      sym_array_number_field,
    STATE(122), 1,
      sym_array_string_field,
    STATE(152), 1,
      sym_string_array,
    STATE(153), 1,
      sym_bool_array,
    STATE(154), 1,
      sym_number_array,
    STATE(235), 1,
      sym_map_string_array_field,
    ACTIONS(352), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [272] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    STATE(239), 1,
      sym__string_array_expansion,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [334] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    STATE(240), 1,
      sym__string_array_expansion,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [396] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    STATE(214), 1,
      sym__string_array_expansion,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [458] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    STATE(215), 1,
      sym__string_array_expansion,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [520] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    STATE(251), 1,
      sym__string_array_expansion,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [582] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    STATE(238), 1,
      sym__string_array_expansion,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [644] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(102), 1,
      sym__string_array_expansion,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [706] = 15,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(45), 1,
      anon_sym_http_DOTrequest_DOTcookies,
    ACTIONS(338), 1,
      anon_sym_concat,
    ACTIONS(340), 1,
      anon_sym_lookup_json_string,
    ACTIONS(344), 1,
      anon_sym_regex_replace,
    ACTIONS(346), 1,
      anon_sym_remove_bytes,
    ACTIONS(348), 1,
      anon_sym_to_string,
    ACTIONS(350), 1,
      anon_sym_uuidv4,
    STATE(122), 1,
      sym_array_string_field,
    STATE(164), 1,
      sym_string_array,
    STATE(199), 1,
      sym_map_string_array_field,
    STATE(213), 1,
      sym__string_array_expansion,
    ACTIONS(342), 3,
      anon_sym_lower,
      anon_sym_upper,
      anon_sym_url_decode,
    ACTIONS(47), 5,
      anon_sym_http_DOTrequest_DOTuri_DOTargs,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs,
      anon_sym_http_DOTrequest_DOTheaders,
      anon_sym_http_DOTrequest_DOTbody_DOTform,
      anon_sym_http_DOTresponse_DOTheaders,
    ACTIONS(318), 11,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_http_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTnames,
      anon_sym_raw_DOThttp_DOTrequest_DOTuri_DOTargs_DOTvalues,
      anon_sym_http_DOTrequest_DOTheaders_DOTnames,
      anon_sym_http_DOTrequest_DOTheaders_DOTvalues,
      anon_sym_http_DOTrequest_DOTaccepted_languages,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTnames,
      anon_sym_http_DOTrequest_DOTbody_DOTform_DOTvalues,
      anon_sym_http_DOTresponse_DOTheaders_DOTnames,
      anon_sym_http_DOTresponse_DOTheaders_DOTvalues,
  [768] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(354), 1,
      anon_sym_in,
    ACTIONS(358), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(356), 13,
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
  [794] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(360), 1,
      anon_sym_in,
    ACTIONS(364), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(362), 13,
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
  [820] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(368), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(366), 12,
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
  [842] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(372), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(370), 12,
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
  [864] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(376), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(374), 12,
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
  [886] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(380), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(378), 11,
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
  [907] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(382), 1,
      anon_sym_in,
    ACTIONS(386), 2,
      anon_sym_LT,
      anon_sym_GT,
    ACTIONS(384), 10,
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
  [930] = 4,
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
  [953] = 5,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(394), 1,
      anon_sym_RPAREN,
    ACTIONS(143), 2,
      anon_sym_AMP_AMP,
      anon_sym_and,
    ACTIONS(145), 2,
      anon_sym_xor,
      anon_sym_CARET_CARET,
    ACTIONS(211), 2,
      anon_sym_or,
      anon_sym_PIPE_PIPE,
  [972] = 6,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(332), 1,
      anon_sym_len,
    ACTIONS(336), 1,
      anon_sym_cf_DOTbot_management_DOTdetection_ids,
    STATE(121), 1,
      sym_array_number_field,
    ACTIONS(352), 2,
      anon_sym_ends_with,
      anon_sym_starts_with,
    STATE(168), 2,
      sym_number_array,
      sym_bool_array,
  [993] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(396), 6,
      anon_sym_in,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
      anon_sym_RPAREN,
  [1005] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(398), 1,
      anon_sym_RBRACE,
    ACTIONS(400), 1,
      sym_ipv4,
    STATE(86), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1020] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(403), 1,
      anon_sym_in,
    ACTIONS(405), 4,
      anon_sym_eq,
      anon_sym_ne,
      anon_sym_EQ_EQ,
      anon_sym_BANG_EQ,
  [1033] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(407), 1,
      anon_sym_RBRACE,
    ACTIONS(409), 1,
      sym_ipv4,
    STATE(86), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1048] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(411), 1,
      anon_sym_RPAREN,
    STATE(95), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(413), 2,
      sym_number,
      sym_string,
  [1062] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(415), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1072] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 1,
      sym_ipv4,
    STATE(88), 3,
      sym__ip,
      sym_ip_range,
      aux_sym_ip_set_repeat1,
  [1084] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(417), 4,
      anon_sym_COMMA,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1094] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(419), 1,
      anon_sym_COMMA,
    ACTIONS(421), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1106] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(423), 1,
      anon_sym_RPAREN,
    STATE(95), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(413), 2,
      sym_number,
      sym_string,
  [1120] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(425), 1,
      anon_sym_RPAREN,
    STATE(95), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(427), 2,
      sym_number,
      sym_string,
  [1134] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(430), 1,
      anon_sym_RPAREN,
    STATE(95), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(413), 2,
      sym_number,
      sym_string,
  [1148] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(432), 1,
      anon_sym_RBRACE,
    ACTIONS(434), 1,
      sym_string,
    STATE(97), 1,
      aux_sym_string_set_repeat1,
  [1161] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(425), 3,
      anon_sym_RPAREN,
      sym_number,
      sym_string,
  [1170] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(437), 1,
      anon_sym_RBRACE,
    ACTIONS(439), 1,
      sym_number,
    STATE(103), 1,
      aux_sym_number_set_repeat1,
  [1183] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(409), 1,
      sym_ipv4,
    STATE(13), 2,
      sym__ip,
      sym_ip_range,
  [1194] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(441), 1,
      anon_sym_LBRACE,
    ACTIONS(443), 1,
      sym_ip_list,
    STATE(21), 1,
      sym_ip_set,
  [1207] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(94), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(413), 2,
      sym_number,
      sym_string,
  [1218] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(445), 1,
      anon_sym_RBRACE,
    ACTIONS(447), 1,
      sym_number,
    STATE(103), 1,
      aux_sym_number_set_repeat1,
  [1231] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(89), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(413), 2,
      sym_number,
      sym_string,
  [1242] = 4,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(450), 1,
      anon_sym_RBRACE,
    ACTIONS(452), 1,
      sym_string,
    STATE(97), 1,
      aux_sym_string_set_repeat1,
  [1255] = 3,
    ACTIONS(3), 1,
      sym_comment,
    STATE(96), 1,
      aux_sym_string_func_repeat2,
    ACTIONS(413), 2,
      sym_number,
      sym_string,
  [1266] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(454), 1,
      anon_sym_LBRACE,
    STATE(192), 1,
      sym_number_set,
  [1276] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(456), 1,
      sym_string,
    STATE(105), 1,
      aux_sym_string_set_repeat1,
  [1286] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(458), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(460), 1,
      anon_sym_LBRACK,
  [1296] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(454), 1,
      anon_sym_LBRACE,
    STATE(21), 1,
      sym_number_set,
  [1306] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(464), 1,
      anon_sym_LBRACK,
  [1316] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(466), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(468), 1,
      anon_sym_LBRACK,
  [1326] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(470), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(472), 1,
      anon_sym_LBRACK,
  [1336] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(474), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(476), 1,
      anon_sym_LBRACK,
  [1346] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(478), 1,
      sym_string,
    ACTIONS(480), 1,
      anon_sym_STAR,
  [1356] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(482), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(484), 1,
      anon_sym_LBRACK,
  [1366] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(486), 1,
      sym_number,
    STATE(99), 1,
      aux_sym_number_set_repeat1,
  [1376] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(490), 1,
      anon_sym_LBRACK,
  [1386] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(492), 1,
      anon_sym_LBRACE,
    STATE(21), 1,
      sym_string_set,
  [1396] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(496), 1,
      anon_sym_LBRACK,
  [1406] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(498), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(500), 1,
      anon_sym_LBRACK,
  [1416] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(502), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(504), 1,
      anon_sym_LBRACK,
  [1426] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(506), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(508), 1,
      anon_sym_LBRACK,
  [1436] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(512), 1,
      anon_sym_LBRACK,
  [1446] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(516), 1,
      anon_sym_LBRACK,
  [1456] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(518), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(520), 1,
      anon_sym_LBRACK,
  [1466] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(522), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [1474] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(526), 1,
      anon_sym_LBRACK,
  [1484] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(492), 1,
      anon_sym_LBRACE,
    STATE(192), 1,
      sym_string_set,
  [1494] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(530), 1,
      anon_sym_LBRACK,
  [1504] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(532), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(534), 1,
      anon_sym_LBRACK,
  [1514] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(462), 1,
      anon_sym_LBRACK_STAR_RBRACK,
    ACTIONS(534), 1,
      anon_sym_LBRACK,
  [1524] = 3,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(464), 1,
      anon_sym_LBRACK,
    ACTIONS(532), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [1534] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(536), 1,
      anon_sym_RPAREN,
  [1541] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(538), 1,
      sym_string,
  [1548] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(540), 1,
      sym_string,
  [1555] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(470), 1,
      anon_sym_LBRACK,
  [1562] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(482), 1,
      anon_sym_LBRACK,
  [1569] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(542), 1,
      anon_sym_LPAREN,
  [1576] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(544), 1,
      sym_string,
  [1583] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(546), 1,
      sym_string,
  [1590] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(548), 1,
      anon_sym_RPAREN,
  [1597] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(550), 1,
      sym_string,
  [1604] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(552), 1,
      sym_string,
  [1611] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(488), 1,
      anon_sym_LBRACK,
  [1618] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(554), 1,
      anon_sym_RBRACK,
  [1625] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(556), 1,
      anon_sym_RBRACK,
  [1632] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(558), 1,
      anon_sym_RBRACK,
  [1639] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(560), 1,
      anon_sym_RBRACK,
  [1646] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(562), 1,
      aux_sym_ip_range_token1,
  [1653] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(458), 1,
      anon_sym_LBRACK,
  [1660] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(564), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [1667] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(566), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [1674] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(568), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [1681] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(570), 1,
      anon_sym_RBRACK,
  [1688] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(572), 1,
      anon_sym_LPAREN,
  [1695] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(466), 1,
      anon_sym_LBRACK,
  [1702] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(574), 1,
      anon_sym_LPAREN,
  [1709] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(576), 1,
      anon_sym_LPAREN,
  [1716] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(578), 1,
      anon_sym_COMMA,
  [1723] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(580), 1,
      anon_sym_COMMA,
  [1730] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(582), 1,
      anon_sym_RPAREN,
  [1737] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(584), 1,
      anon_sym_RPAREN,
  [1744] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(524), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [1751] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(474), 1,
      anon_sym_LBRACK,
  [1758] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(586), 1,
      anon_sym_RPAREN,
  [1765] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(588), 1,
      anon_sym_RPAREN,
  [1772] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(532), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [1779] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(590), 1,
      anon_sym_LPAREN,
  [1786] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(592), 1,
      sym_number,
  [1793] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(594), 1,
      anon_sym_LPAREN,
  [1800] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(596), 1,
      anon_sym_LPAREN,
  [1807] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(592), 1,
      sym_string,
  [1814] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(598), 1,
      anon_sym_LPAREN,
  [1821] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(600), 1,
      anon_sym_LPAREN,
  [1828] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(602), 1,
      anon_sym_COMMA,
  [1835] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(604), 1,
      anon_sym_COMMA,
  [1842] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(606), 1,
      anon_sym_RPAREN,
  [1849] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(608), 1,
      anon_sym_RPAREN,
  [1856] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(610), 1,
      anon_sym_RPAREN,
  [1863] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(612), 1,
      anon_sym_RPAREN,
  [1870] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(614), 1,
      anon_sym_LPAREN,
  [1877] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(616), 1,
      anon_sym_COMMA,
  [1884] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(494), 1,
      anon_sym_LBRACK,
  [1891] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(618), 1,
      anon_sym_LBRACK_STAR_RBRACK,
  [1898] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(620), 1,
      sym_string,
  [1905] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(622), 1,
      sym_string,
  [1912] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(510), 1,
      anon_sym_LBRACK,
  [1919] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(624), 1,
      anon_sym_COMMA,
  [1926] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(514), 1,
      anon_sym_LBRACK,
  [1933] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(626), 1,
      anon_sym_COMMA,
  [1940] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(628), 1,
      anon_sym_RPAREN,
  [1947] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(630), 1,
      anon_sym_COMMA,
  [1954] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(632), 1,
      anon_sym_RPAREN,
  [1961] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(634), 1,
      anon_sym_RPAREN,
  [1968] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(636), 1,
      anon_sym_RPAREN,
  [1975] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(518), 1,
      anon_sym_LBRACK,
  [1982] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(638), 1,
      anon_sym_RPAREN,
  [1989] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(640), 1,
      anon_sym_LBRACK,
  [1996] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(642), 1,
      anon_sym_COMMA,
  [2003] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(644), 1,
      anon_sym_COMMA,
  [2010] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(646), 1,
      sym_string,
  [2017] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(648), 1,
      sym_string,
  [2024] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(650), 1,
      sym_number,
  [2031] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(652), 1,
      sym_number,
  [2038] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(654), 1,
      sym_number,
  [2045] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(648), 1,
      sym_number,
  [2052] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(498), 1,
      anon_sym_LBRACK,
  [2059] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(502), 1,
      anon_sym_LBRACK,
  [2066] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(656), 1,
      anon_sym_LBRACK,
  [2073] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(658), 1,
      anon_sym_LBRACK,
  [2080] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(660), 1,
      anon_sym_LBRACK,
  [2087] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(662), 1,
      anon_sym_RPAREN,
  [2094] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(664), 1,
      anon_sym_RPAREN,
  [2101] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(666), 1,
      anon_sym_RPAREN,
  [2108] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(668), 1,
      anon_sym_RBRACK,
  [2115] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(670), 1,
      anon_sym_LBRACK,
  [2122] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(672), 1,
      anon_sym_RPAREN,
  [2129] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(674), 1,
      ts_builtin_sym_end,
  [2136] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(676), 1,
      anon_sym_RPAREN,
  [2143] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(678), 1,
      anon_sym_RPAREN,
  [2150] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(680), 1,
      anon_sym_RPAREN,
  [2157] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(506), 1,
      anon_sym_LBRACK,
  [2164] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(528), 1,
      anon_sym_LBRACK,
  [2171] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(478), 1,
      sym_string,
  [2178] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(682), 1,
      anon_sym_LBRACK,
  [2185] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(684), 1,
      anon_sym_LPAREN,
  [2192] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(686), 1,
      anon_sym_LPAREN,
  [2199] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(688), 1,
      anon_sym_LPAREN,
  [2206] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(690), 1,
      sym_string,
  [2213] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(692), 1,
      sym_string,
  [2220] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(694), 1,
      sym_string,
  [2227] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(696), 1,
      anon_sym_LPAREN,
  [2234] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(698), 1,
      anon_sym_LPAREN,
  [2241] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(700), 1,
      anon_sym_LBRACK,
  [2248] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(702), 1,
      anon_sym_LPAREN,
  [2255] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(704), 1,
      anon_sym_LPAREN,
  [2262] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(706), 1,
      anon_sym_COMMA,
  [2269] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(708), 1,
      anon_sym_COMMA,
  [2276] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(710), 1,
      anon_sym_COMMA,
  [2283] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(712), 1,
      anon_sym_COMMA,
  [2290] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(714), 1,
      anon_sym_LPAREN,
  [2297] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(716), 1,
      anon_sym_LPAREN,
  [2304] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(718), 1,
      anon_sym_LPAREN,
  [2311] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(720), 1,
      anon_sym_LPAREN,
  [2318] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(722), 1,
      anon_sym_LPAREN,
  [2325] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(724), 1,
      sym_string,
  [2332] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(726), 1,
      anon_sym_LPAREN,
  [2339] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(728), 1,
      anon_sym_LPAREN,
  [2346] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(730), 1,
      anon_sym_LPAREN,
  [2353] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(732), 1,
      anon_sym_COMMA,
  [2360] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(734), 1,
      anon_sym_LPAREN,
  [2367] = 2,
    ACTIONS(3), 1,
      sym_comment,
    ACTIONS(736), 1,
      anon_sym_LPAREN,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(64)] = 0,
  [SMALL_STATE(65)] = 97,
  [SMALL_STATE(66)] = 194,
  [SMALL_STATE(67)] = 272,
  [SMALL_STATE(68)] = 334,
  [SMALL_STATE(69)] = 396,
  [SMALL_STATE(70)] = 458,
  [SMALL_STATE(71)] = 520,
  [SMALL_STATE(72)] = 582,
  [SMALL_STATE(73)] = 644,
  [SMALL_STATE(74)] = 706,
  [SMALL_STATE(75)] = 768,
  [SMALL_STATE(76)] = 794,
  [SMALL_STATE(77)] = 820,
  [SMALL_STATE(78)] = 842,
  [SMALL_STATE(79)] = 864,
  [SMALL_STATE(80)] = 886,
  [SMALL_STATE(81)] = 907,
  [SMALL_STATE(82)] = 930,
  [SMALL_STATE(83)] = 953,
  [SMALL_STATE(84)] = 972,
  [SMALL_STATE(85)] = 993,
  [SMALL_STATE(86)] = 1005,
  [SMALL_STATE(87)] = 1020,
  [SMALL_STATE(88)] = 1033,
  [SMALL_STATE(89)] = 1048,
  [SMALL_STATE(90)] = 1062,
  [SMALL_STATE(91)] = 1072,
  [SMALL_STATE(92)] = 1084,
  [SMALL_STATE(93)] = 1094,
  [SMALL_STATE(94)] = 1106,
  [SMALL_STATE(95)] = 1120,
  [SMALL_STATE(96)] = 1134,
  [SMALL_STATE(97)] = 1148,
  [SMALL_STATE(98)] = 1161,
  [SMALL_STATE(99)] = 1170,
  [SMALL_STATE(100)] = 1183,
  [SMALL_STATE(101)] = 1194,
  [SMALL_STATE(102)] = 1207,
  [SMALL_STATE(103)] = 1218,
  [SMALL_STATE(104)] = 1231,
  [SMALL_STATE(105)] = 1242,
  [SMALL_STATE(106)] = 1255,
  [SMALL_STATE(107)] = 1266,
  [SMALL_STATE(108)] = 1276,
  [SMALL_STATE(109)] = 1286,
  [SMALL_STATE(110)] = 1296,
  [SMALL_STATE(111)] = 1306,
  [SMALL_STATE(112)] = 1316,
  [SMALL_STATE(113)] = 1326,
  [SMALL_STATE(114)] = 1336,
  [SMALL_STATE(115)] = 1346,
  [SMALL_STATE(116)] = 1356,
  [SMALL_STATE(117)] = 1366,
  [SMALL_STATE(118)] = 1376,
  [SMALL_STATE(119)] = 1386,
  [SMALL_STATE(120)] = 1396,
  [SMALL_STATE(121)] = 1406,
  [SMALL_STATE(122)] = 1416,
  [SMALL_STATE(123)] = 1426,
  [SMALL_STATE(124)] = 1436,
  [SMALL_STATE(125)] = 1446,
  [SMALL_STATE(126)] = 1456,
  [SMALL_STATE(127)] = 1466,
  [SMALL_STATE(128)] = 1474,
  [SMALL_STATE(129)] = 1484,
  [SMALL_STATE(130)] = 1494,
  [SMALL_STATE(131)] = 1504,
  [SMALL_STATE(132)] = 1514,
  [SMALL_STATE(133)] = 1524,
  [SMALL_STATE(134)] = 1534,
  [SMALL_STATE(135)] = 1541,
  [SMALL_STATE(136)] = 1548,
  [SMALL_STATE(137)] = 1555,
  [SMALL_STATE(138)] = 1562,
  [SMALL_STATE(139)] = 1569,
  [SMALL_STATE(140)] = 1576,
  [SMALL_STATE(141)] = 1583,
  [SMALL_STATE(142)] = 1590,
  [SMALL_STATE(143)] = 1597,
  [SMALL_STATE(144)] = 1604,
  [SMALL_STATE(145)] = 1611,
  [SMALL_STATE(146)] = 1618,
  [SMALL_STATE(147)] = 1625,
  [SMALL_STATE(148)] = 1632,
  [SMALL_STATE(149)] = 1639,
  [SMALL_STATE(150)] = 1646,
  [SMALL_STATE(151)] = 1653,
  [SMALL_STATE(152)] = 1660,
  [SMALL_STATE(153)] = 1667,
  [SMALL_STATE(154)] = 1674,
  [SMALL_STATE(155)] = 1681,
  [SMALL_STATE(156)] = 1688,
  [SMALL_STATE(157)] = 1695,
  [SMALL_STATE(158)] = 1702,
  [SMALL_STATE(159)] = 1709,
  [SMALL_STATE(160)] = 1716,
  [SMALL_STATE(161)] = 1723,
  [SMALL_STATE(162)] = 1730,
  [SMALL_STATE(163)] = 1737,
  [SMALL_STATE(164)] = 1744,
  [SMALL_STATE(165)] = 1751,
  [SMALL_STATE(166)] = 1758,
  [SMALL_STATE(167)] = 1765,
  [SMALL_STATE(168)] = 1772,
  [SMALL_STATE(169)] = 1779,
  [SMALL_STATE(170)] = 1786,
  [SMALL_STATE(171)] = 1793,
  [SMALL_STATE(172)] = 1800,
  [SMALL_STATE(173)] = 1807,
  [SMALL_STATE(174)] = 1814,
  [SMALL_STATE(175)] = 1821,
  [SMALL_STATE(176)] = 1828,
  [SMALL_STATE(177)] = 1835,
  [SMALL_STATE(178)] = 1842,
  [SMALL_STATE(179)] = 1849,
  [SMALL_STATE(180)] = 1856,
  [SMALL_STATE(181)] = 1863,
  [SMALL_STATE(182)] = 1870,
  [SMALL_STATE(183)] = 1877,
  [SMALL_STATE(184)] = 1884,
  [SMALL_STATE(185)] = 1891,
  [SMALL_STATE(186)] = 1898,
  [SMALL_STATE(187)] = 1905,
  [SMALL_STATE(188)] = 1912,
  [SMALL_STATE(189)] = 1919,
  [SMALL_STATE(190)] = 1926,
  [SMALL_STATE(191)] = 1933,
  [SMALL_STATE(192)] = 1940,
  [SMALL_STATE(193)] = 1947,
  [SMALL_STATE(194)] = 1954,
  [SMALL_STATE(195)] = 1961,
  [SMALL_STATE(196)] = 1968,
  [SMALL_STATE(197)] = 1975,
  [SMALL_STATE(198)] = 1982,
  [SMALL_STATE(199)] = 1989,
  [SMALL_STATE(200)] = 1996,
  [SMALL_STATE(201)] = 2003,
  [SMALL_STATE(202)] = 2010,
  [SMALL_STATE(203)] = 2017,
  [SMALL_STATE(204)] = 2024,
  [SMALL_STATE(205)] = 2031,
  [SMALL_STATE(206)] = 2038,
  [SMALL_STATE(207)] = 2045,
  [SMALL_STATE(208)] = 2052,
  [SMALL_STATE(209)] = 2059,
  [SMALL_STATE(210)] = 2066,
  [SMALL_STATE(211)] = 2073,
  [SMALL_STATE(212)] = 2080,
  [SMALL_STATE(213)] = 2087,
  [SMALL_STATE(214)] = 2094,
  [SMALL_STATE(215)] = 2101,
  [SMALL_STATE(216)] = 2108,
  [SMALL_STATE(217)] = 2115,
  [SMALL_STATE(218)] = 2122,
  [SMALL_STATE(219)] = 2129,
  [SMALL_STATE(220)] = 2136,
  [SMALL_STATE(221)] = 2143,
  [SMALL_STATE(222)] = 2150,
  [SMALL_STATE(223)] = 2157,
  [SMALL_STATE(224)] = 2164,
  [SMALL_STATE(225)] = 2171,
  [SMALL_STATE(226)] = 2178,
  [SMALL_STATE(227)] = 2185,
  [SMALL_STATE(228)] = 2192,
  [SMALL_STATE(229)] = 2199,
  [SMALL_STATE(230)] = 2206,
  [SMALL_STATE(231)] = 2213,
  [SMALL_STATE(232)] = 2220,
  [SMALL_STATE(233)] = 2227,
  [SMALL_STATE(234)] = 2234,
  [SMALL_STATE(235)] = 2241,
  [SMALL_STATE(236)] = 2248,
  [SMALL_STATE(237)] = 2255,
  [SMALL_STATE(238)] = 2262,
  [SMALL_STATE(239)] = 2269,
  [SMALL_STATE(240)] = 2276,
  [SMALL_STATE(241)] = 2283,
  [SMALL_STATE(242)] = 2290,
  [SMALL_STATE(243)] = 2297,
  [SMALL_STATE(244)] = 2304,
  [SMALL_STATE(245)] = 2311,
  [SMALL_STATE(246)] = 2318,
  [SMALL_STATE(247)] = 2325,
  [SMALL_STATE(248)] = 2332,
  [SMALL_STATE(249)] = 2339,
  [SMALL_STATE(250)] = 2346,
  [SMALL_STATE(251)] = 2353,
  [SMALL_STATE(252)] = 2360,
  [SMALL_STATE(253)] = 2367,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, SHIFT_EXTRA(),
  [5] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 0),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(139),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(252),
  [13] = {.entry = {.count = 1, .reusable = true}}, SHIFT(246),
  [15] = {.entry = {.count = 1, .reusable = true}}, SHIFT(245),
  [17] = {.entry = {.count = 1, .reusable = true}}, SHIFT(244),
  [19] = {.entry = {.count = 1, .reusable = true}}, SHIFT(237),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(236),
  [23] = {.entry = {.count = 1, .reusable = true}}, SHIFT(229),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(228),
  [27] = {.entry = {.count = 1, .reusable = true}}, SHIFT(227),
  [29] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [31] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [33] = {.entry = {.count = 1, .reusable = true}}, SHIFT(78),
  [35] = {.entry = {.count = 1, .reusable = false}}, SHIFT(78),
  [37] = {.entry = {.count = 1, .reusable = false}}, SHIFT(85),
  [39] = {.entry = {.count = 1, .reusable = true}}, SHIFT(85),
  [41] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [43] = {.entry = {.count = 1, .reusable = false}}, SHIFT(31),
  [45] = {.entry = {.count = 1, .reusable = true}}, SHIFT(226),
  [47] = {.entry = {.count = 1, .reusable = false}}, SHIFT(226),
  [49] = {.entry = {.count = 1, .reusable = true}}, SHIFT(224),
  [51] = {.entry = {.count = 1, .reusable = true}}, SHIFT(223),
  [53] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [55] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2),
  [57] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(139),
  [60] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(5),
  [63] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(252),
  [66] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(246),
  [69] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(245),
  [72] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(244),
  [75] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(237),
  [78] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(236),
  [81] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(229),
  [84] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(228),
  [87] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(227),
  [90] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(15),
  [93] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(30),
  [96] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(78),
  [99] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(78),
  [102] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(85),
  [105] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(85),
  [108] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(31),
  [111] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(31),
  [114] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(226),
  [117] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(226),
  [120] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(224),
  [123] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(223),
  [126] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 2), SHIFT_REPEAT(22),
  [129] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_source_file, 1),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__ip, 1),
  [133] = {.entry = {.count = 1, .reusable = true}}, SHIFT(150),
  [135] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__ip, 1),
  [137] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [139] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_range, 3, .production_id = 13),
  [141] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_compound_expression, 3, .production_id = 2),
  [143] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [145] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [147] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_compound_expression, 3, .production_id = 2),
  [149] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [151] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_simple_expression, 3, .production_id = 2),
  [153] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_expression, 2),
  [155] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_expression, 2),
  [157] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boolean, 1),
  [159] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boolean, 1),
  [161] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 6, .production_id = 18),
  [163] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 6, .production_id = 18),
  [165] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_func, 7, .production_id = 19),
  [167] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_func, 7, .production_id = 19),
  [169] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boollike_field, 4, .production_id = 7),
  [171] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boollike_field, 4, .production_id = 7),
  [173] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_set, 3),
  [175] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_ip_set, 3),
  [177] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_group, 3, .production_id = 1),
  [179] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_group, 3, .production_id = 1),
  [181] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [183] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_in_expression, 3, .production_id = 2),
  [185] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_field, 1),
  [187] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_field, 1),
  [189] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_boollike_field, 1),
  [191] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_boollike_field, 1),
  [193] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_func, 1),
  [195] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_func, 1),
  [197] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_set, 3),
  [199] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_set, 3),
  [201] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_set, 3),
  [203] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_set, 3),
  [205] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_func, 5, .production_id = 12),
  [207] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_func, 5, .production_id = 12),
  [209] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [211] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [213] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_source_file_repeat1, 1),
  [215] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_not_operator, 1),
  [217] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_not_operator, 1),
  [219] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_field, 1),
  [221] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_field, 1),
  [223] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 5, .production_id = 10),
  [225] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 5, .production_id = 10),
  [227] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_stringlike_field, 1),
  [229] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_stringlike_field, 1),
  [231] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 4),
  [233] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 4),
  [235] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 12),
  [237] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 12),
  [239] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 4, .production_id = 6),
  [241] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 4, .production_id = 6),
  [243] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 8, .production_id = 21),
  [245] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 8, .production_id = 21),
  [247] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [249] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_func, 6, .production_id = 16),
  [251] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_stringlike_field, 4, .production_id = 7),
  [253] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_stringlike_field, 4, .production_id = 7),
  [255] = {.entry = {.count = 1, .reusable = true}}, SHIFT(35),
  [257] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [259] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(139),
  [262] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [264] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(252),
  [267] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(246),
  [270] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(245),
  [273] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(244),
  [276] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(237),
  [279] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(236),
  [282] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(62),
  [285] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(31),
  [288] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(31),
  [291] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(226),
  [294] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(226),
  [297] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 2), SHIFT_REPEAT(224),
  [300] = {.entry = {.count = 1, .reusable = true}}, SHIFT(120),
  [302] = {.entry = {.count = 1, .reusable = true}}, SHIFT(248),
  [304] = {.entry = {.count = 1, .reusable = true}}, SHIFT(242),
  [306] = {.entry = {.count = 1, .reusable = true}}, SHIFT(233),
  [308] = {.entry = {.count = 1, .reusable = true}}, SHIFT(253),
  [310] = {.entry = {.count = 1, .reusable = true}}, SHIFT(249),
  [312] = {.entry = {.count = 1, .reusable = true}}, SHIFT(243),
  [314] = {.entry = {.count = 1, .reusable = true}}, SHIFT(234),
  [316] = {.entry = {.count = 1, .reusable = true}}, SHIFT(127),
  [318] = {.entry = {.count = 1, .reusable = true}}, SHIFT(130),
  [320] = {.entry = {.count = 1, .reusable = true}}, SHIFT(184),
  [322] = {.entry = {.count = 1, .reusable = true}}, SHIFT(201),
  [324] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [326] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [328] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 1),
  [330] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_string_func_repeat1, 2),
  [332] = {.entry = {.count = 1, .reusable = true}}, SHIFT(182),
  [334] = {.entry = {.count = 1, .reusable = true}}, SHIFT(250),
  [336] = {.entry = {.count = 1, .reusable = true}}, SHIFT(123),
  [338] = {.entry = {.count = 1, .reusable = true}}, SHIFT(175),
  [340] = {.entry = {.count = 1, .reusable = true}}, SHIFT(174),
  [342] = {.entry = {.count = 1, .reusable = true}}, SHIFT(172),
  [344] = {.entry = {.count = 1, .reusable = true}}, SHIFT(171),
  [346] = {.entry = {.count = 1, .reusable = true}}, SHIFT(169),
  [348] = {.entry = {.count = 1, .reusable = true}}, SHIFT(159),
  [350] = {.entry = {.count = 1, .reusable = true}}, SHIFT(158),
  [352] = {.entry = {.count = 1, .reusable = true}}, SHIFT(156),
  [354] = {.entry = {.count = 1, .reusable = true}}, SHIFT(129),
  [356] = {.entry = {.count = 1, .reusable = true}}, SHIFT(173),
  [358] = {.entry = {.count = 1, .reusable = false}}, SHIFT(173),
  [360] = {.entry = {.count = 1, .reusable = true}}, SHIFT(119),
  [362] = {.entry = {.count = 1, .reusable = true}}, SHIFT(203),
  [364] = {.entry = {.count = 1, .reusable = false}}, SHIFT(203),
  [366] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_numberlike_field, 1),
  [368] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_numberlike_field, 1),
  [370] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_field, 1),
  [372] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_field, 1),
  [374] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_numberlike_field, 4, .production_id = 7),
  [376] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_numberlike_field, 4, .production_id = 7),
  [378] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_func, 4, .production_id = 4),
  [380] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_func, 4, .production_id = 4),
  [382] = {.entry = {.count = 1, .reusable = true}}, SHIFT(110),
  [384] = {.entry = {.count = 1, .reusable = true}}, SHIFT(207),
  [386] = {.entry = {.count = 1, .reusable = false}}, SHIFT(207),
  [388] = {.entry = {.count = 1, .reusable = true}}, SHIFT(107),
  [390] = {.entry = {.count = 1, .reusable = true}}, SHIFT(170),
  [392] = {.entry = {.count = 1, .reusable = false}}, SHIFT(170),
  [394] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [396] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_ip_field, 1),
  [398] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2),
  [400] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_ip_set_repeat1, 2), SHIFT_REPEAT(9),
  [403] = {.entry = {.count = 1, .reusable = true}}, SHIFT(101),
  [405] = {.entry = {.count = 1, .reusable = true}}, SHIFT(100),
  [407] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [409] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [411] = {.entry = {.count = 1, .reusable = true}}, SHIFT(157),
  [413] = {.entry = {.count = 1, .reusable = true}}, SHIFT(93),
  [415] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 5, .production_id = 8),
  [417] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__string_array_expansion, 2),
  [419] = {.entry = {.count = 1, .reusable = true}}, SHIFT(98),
  [421] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 1),
  [423] = {.entry = {.count = 1, .reusable = true}}, SHIFT(112),
  [425] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2),
  [427] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_func_repeat2, 2), SHIFT_REPEAT(93),
  [430] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [432] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2),
  [434] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_string_set_repeat1, 2), SHIFT_REPEAT(97),
  [437] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [439] = {.entry = {.count = 1, .reusable = true}}, SHIFT(103),
  [441] = {.entry = {.count = 1, .reusable = true}}, SHIFT(91),
  [443] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [445] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2),
  [447] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_set_repeat1, 2), SHIFT_REPEAT(103),
  [450] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [452] = {.entry = {.count = 1, .reusable = true}}, SHIFT(97),
  [454] = {.entry = {.count = 1, .reusable = true}}, SHIFT(117),
  [456] = {.entry = {.count = 1, .reusable = true}}, SHIFT(105),
  [458] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 8),
  [460] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 8),
  [462] = {.entry = {.count = 1, .reusable = true}}, SHIFT(134),
  [464] = {.entry = {.count = 1, .reusable = false}}, SHIFT(206),
  [466] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 5, .production_id = 9),
  [468] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 5, .production_id = 9),
  [470] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_array, 4, .production_id = 3),
  [472] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_array, 4, .production_id = 3),
  [474] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 5, .production_id = 11),
  [476] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 5, .production_id = 11),
  [478] = {.entry = {.count = 1, .reusable = true}}, SHIFT(216),
  [480] = {.entry = {.count = 1, .reusable = true}}, SHIFT(155),
  [482] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 5),
  [484] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 5),
  [486] = {.entry = {.count = 1, .reusable = true}}, SHIFT(99),
  [488] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 4, .production_id = 3),
  [490] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 4, .production_id = 3),
  [492] = {.entry = {.count = 1, .reusable = true}}, SHIFT(108),
  [494] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 6, .production_id = 14),
  [496] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 6, .production_id = 14),
  [498] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_array, 1),
  [500] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_array, 1),
  [502] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 1),
  [504] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 1),
  [506] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_number_field, 1),
  [508] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_number_field, 1),
  [510] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 6, .production_id = 15),
  [512] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 6, .production_id = 15),
  [514] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bool_array, 6, .production_id = 17),
  [516] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_bool_array, 6, .production_id = 17),
  [518] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_string_array, 8, .production_id = 20),
  [520] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_string_array, 8, .production_id = 20),
  [522] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_bytes_field, 1),
  [524] = {.entry = {.count = 1, .reusable = true}}, SHIFT(92),
  [526] = {.entry = {.count = 1, .reusable = false}}, SHIFT(204),
  [528] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_array_string_field, 1),
  [530] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_array_string_field, 1),
  [532] = {.entry = {.count = 1, .reusable = true}}, SHIFT(218),
  [534] = {.entry = {.count = 1, .reusable = false}}, SHIFT(205),
  [536] = {.entry = {.count = 1, .reusable = true}}, SHIFT(165),
  [538] = {.entry = {.count = 1, .reusable = true}}, SHIFT(166),
  [540] = {.entry = {.count = 1, .reusable = true}}, SHIFT(167),
  [542] = {.entry = {.count = 1, .reusable = true}}, SHIFT(50),
  [544] = {.entry = {.count = 1, .reusable = true}}, SHIFT(163),
  [546] = {.entry = {.count = 1, .reusable = true}}, SHIFT(162),
  [548] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [550] = {.entry = {.count = 1, .reusable = true}}, SHIFT(161),
  [552] = {.entry = {.count = 1, .reusable = true}}, SHIFT(160),
  [554] = {.entry = {.count = 1, .reusable = true}}, SHIFT(151),
  [556] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [558] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [560] = {.entry = {.count = 1, .reusable = true}}, SHIFT(79),
  [562] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [564] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [566] = {.entry = {.count = 1, .reusable = true}}, SHIFT(142),
  [568] = {.entry = {.count = 1, .reusable = true}}, SHIFT(82),
  [570] = {.entry = {.count = 1, .reusable = true}}, SHIFT(185),
  [572] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [574] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [576] = {.entry = {.count = 1, .reusable = true}}, SHIFT(84),
  [578] = {.entry = {.count = 1, .reusable = true}}, SHIFT(186),
  [580] = {.entry = {.count = 1, .reusable = true}}, SHIFT(187),
  [582] = {.entry = {.count = 1, .reusable = true}}, SHIFT(188),
  [584] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [586] = {.entry = {.count = 1, .reusable = true}}, SHIFT(190),
  [588] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [590] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
  [592] = {.entry = {.count = 1, .reusable = true}}, SHIFT(192),
  [594] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [596] = {.entry = {.count = 1, .reusable = true}}, SHIFT(74),
  [598] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [600] = {.entry = {.count = 1, .reusable = true}}, SHIFT(72),
  [602] = {.entry = {.count = 1, .reusable = true}}, SHIFT(136),
  [604] = {.entry = {.count = 1, .reusable = true}}, SHIFT(135),
  [606] = {.entry = {.count = 1, .reusable = true}}, SHIFT(80),
  [608] = {.entry = {.count = 1, .reusable = true}}, SHIFT(137),
  [610] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [612] = {.entry = {.count = 1, .reusable = true}}, SHIFT(138),
  [614] = {.entry = {.count = 1, .reusable = true}}, SHIFT(70),
  [616] = {.entry = {.count = 1, .reusable = true}}, SHIFT(140),
  [618] = {.entry = {.count = 1, .reusable = true}}, SHIFT(90),
  [620] = {.entry = {.count = 1, .reusable = true}}, SHIFT(194),
  [622] = {.entry = {.count = 1, .reusable = true}}, SHIFT(195),
  [624] = {.entry = {.count = 1, .reusable = true}}, SHIFT(141),
  [626] = {.entry = {.count = 1, .reusable = true}}, SHIFT(143),
  [628] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [630] = {.entry = {.count = 1, .reusable = true}}, SHIFT(144),
  [632] = {.entry = {.count = 1, .reusable = true}}, SHIFT(197),
  [634] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [636] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [638] = {.entry = {.count = 1, .reusable = true}}, SHIFT(145),
  [640] = {.entry = {.count = 1, .reusable = true}}, SHIFT(115),
  [642] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [644] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [646] = {.entry = {.count = 1, .reusable = true}}, SHIFT(146),
  [648] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [650] = {.entry = {.count = 1, .reusable = true}}, SHIFT(147),
  [652] = {.entry = {.count = 1, .reusable = true}}, SHIFT(148),
  [654] = {.entry = {.count = 1, .reusable = true}}, SHIFT(149),
  [656] = {.entry = {.count = 1, .reusable = true}}, SHIFT(202),
  [658] = {.entry = {.count = 1, .reusable = true}}, SHIFT(204),
  [660] = {.entry = {.count = 1, .reusable = true}}, SHIFT(205),
  [662] = {.entry = {.count = 1, .reusable = true}}, SHIFT(118),
  [664] = {.entry = {.count = 1, .reusable = true}}, SHIFT(116),
  [666] = {.entry = {.count = 1, .reusable = true}}, SHIFT(113),
  [668] = {.entry = {.count = 1, .reusable = true}}, SHIFT(109),
  [670] = {.entry = {.count = 1, .reusable = true}}, SHIFT(206),
  [672] = {.entry = {.count = 1, .reusable = true}}, SHIFT(114),
  [674] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [676] = {.entry = {.count = 1, .reusable = true}}, SHIFT(124),
  [678] = {.entry = {.count = 1, .reusable = true}}, SHIFT(125),
  [680] = {.entry = {.count = 1, .reusable = true}}, SHIFT(126),
  [682] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_map_string_array_field, 1),
  [684] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [686] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [688] = {.entry = {.count = 1, .reusable = true}}, SHIFT(46),
  [690] = {.entry = {.count = 1, .reusable = true}}, SHIFT(220),
  [692] = {.entry = {.count = 1, .reusable = true}}, SHIFT(221),
  [694] = {.entry = {.count = 1, .reusable = true}}, SHIFT(222),
  [696] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [698] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [700] = {.entry = {.count = 1, .reusable = true}}, SHIFT(225),
  [702] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [704] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [706] = {.entry = {.count = 1, .reusable = true}}, SHIFT(51),
  [708] = {.entry = {.count = 1, .reusable = true}}, SHIFT(230),
  [710] = {.entry = {.count = 1, .reusable = true}}, SHIFT(231),
  [712] = {.entry = {.count = 1, .reusable = true}}, SHIFT(232),
  [714] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [716] = {.entry = {.count = 1, .reusable = true}}, SHIFT(65),
  [718] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [720] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [722] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [724] = {.entry = {.count = 1, .reusable = true}}, SHIFT(241),
  [726] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [728] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [730] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [732] = {.entry = {.count = 1, .reusable = true}}, SHIFT(247),
  [734] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [736] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
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
