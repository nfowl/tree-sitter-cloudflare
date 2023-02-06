use std::{env, os};

use anyhow::{anyhow, Result};
use reqwest::header::AUTHORIZATION;
use reqwest::{self, Error};
use tree_sitter;

// fn validate
// func Validate(expression string) error {
// 	expression = sanitize(expression)
// 	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/filters/validate-expr?expression=%s", expression), nil)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("CLOUDFLARE_API_TOKEN")))
//
// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	defer resp.Body.Close()
// 	var v ValidateResult
// 	b, _ := io.ReadAll(resp.Body)
// 	json.Unmarshal(b, &v)
// 	if v.Valid {
// 		return nil
// 	}
//
// 	out := make([]string, 0, 0)
// 	for _, e := range v.Errors {
// 		out = append(out, e.Message)
// 	}
//
// 	return errors.New(strings.Join(out, "\n"))
// }

struct ValidateResult {
    result: String,
    valid: bool,
}

fn validate(expr: &str) -> Result<()> {
    let sanitized = expr.replace(" ", "");
    let api_token = env::var("CLOUDFLARE_API_TOKEN").unwrap();
    let response = reqwest::blocking::Client::new()
        .get(format!(
            "https://api.cloudflare.com/client/v4/filters/validate-expr?expression={}",
            sanitized
        ))
        .bearer_auth(api_token)
        .send()?;
    println!("{:?}", response);
    Ok(())
}

// fn parse(input: String) -> bool {
//     let mut parser = tree_sitter::Parser::new();
//     // info!("Parsing input");
//     parser
//         .set_language(tree_sitter_cloudflare::language())
//         .unwrap();
//     let tree = parser
//         .parse(input.clone(), None)
//         // .ok_or_else(|| anyhow!("Invalid input expression"))
//         .unwrap();
//     let cursor = tree.walk();
//     true
// }

#[test]
fn integration_test() {
    validate("ssl").expect("aa");
    assert!(false)
}
