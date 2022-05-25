use bitcoin::Transaction;

use crate::{AnalysisResult, Heuristics};

pub fn check_round_number(tx: &Transaction) -> AnalysisResult {
    //assuming payments have only 2 decimal places and only applies
    //to simple spend
    const PRECISION: u64 = 5;
    let output_values: Vec<u64> = tx.output.iter().map(|out| out.value).collect();

    let mut check_freq_res = vec![true; output_values.len()];
    for (i, output_value) in output_values.iter().enumerate() {
        let mut prev_char = ' ';
        for (j, c) in output_value
            .to_string()
            .chars()
            .collect::<Vec<char>>()
            .iter()
            .enumerate()
        {
            if j != 0 && prev_char != *c {
                check_freq_res[i] = false;
            }

            prev_char = *c;
        }
    }

    let passed_freq_test = check_freq_res.iter().any(|x| *x);
    let mut result = false;

    if !passed_freq_test {
        for output_value in output_values.clone() {
            for i in 0..PRECISION {
                if output_value % 10u64.pow(i as u32) != 0 {
                    result = true;
                }
            }
        }
    }

    return AnalysisResult {
        heuristic: Heuristics::RoundNumber,
        result: passed_freq_test || result,
        details: String::from("Found round number in outputs"),
        template: false,
        change_addr: None,
    };
}
