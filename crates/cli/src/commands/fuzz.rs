use anyhow::Result;

pub async fn run(url: String, param: String, wordlist: Option<String>, threads: usize) -> Result<()> {
    println!("Starting fuzzing of parameter '{}' on URL: {}", param, url);
    println!("Threads: {}", threads);

    if let Some(wordlist) = wordlist {
        println!("Using wordlist: {}", wordlist);
    } else {
        println!("Using default wordlist");
    }

    // TODO: Implement fuzzing
    println!("Fuzzing not yet implemented");

    Ok(())
}
