use bitcoin::Transaction;

use crate::{AnalysisResult, Heuristics};

pub fn check_equaloutput_coinjoin(tx: &Transaction) -> AnalysisResult {
    // Assumption: we have a coinjoin transaction
    // check the output for equal payment amounts
    // return an analysis result
    const SAT_PER_BTC: f64 = 100_000_000.0;

    let output_values: Vec<f64> = tx
        .output
        .iter()
        .map(|out| out.value as f64 / SAT_PER_BTC)
        .collect();
    let mut result = false;
    for (index, &value) in output_values.iter().enumerate() {
        for (i, &v) in output_values.iter().enumerate() {
            if index == i {
                continue;
            }

            if value == v {
                result = true;
                break;
            }
        }
    }

    return AnalysisResult {
        heuristic: Heuristics::Coinjoin,
        result,
        details: String::from("Found Equal Outputs Coinjoin"),
        template: false,
        change_addr: None,
    };
}
