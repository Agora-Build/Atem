use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::Write;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

pub async fn copy(text: &str) -> Result<&'static str> {
    if text.is_empty() {
        bail!("No terminal text to copy");
    }
    if text.len() > 100_000 {
        bail!("Selection exceeds the 100 KB clipboard limit");
    }
    if std::env::var_os("TMUX").is_some() {
        let mut child = tokio::process::Command::new("tmux")
            .args(["load-buffer", "-w", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Could not open the tmux clipboard")?;
        let mut stdin = child.stdin.take().unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            stdin.write_all(text.as_bytes()).await?;
            drop(stdin);
            child.wait_with_output().await
        })
        .await
        .context("tmux clipboard request timed out")??;
        if !result.status.success() {
            bail!("tmux rejected the clipboard request");
        }
        Ok("Copied to tmux buffer; system clipboard requested")
    } else {
        write_osc52(&mut std::io::stdout(), text)?;
        Ok("Clipboard request sent; terminal must allow OSC 52")
    }
}

fn write_osc52(writer: &mut impl Write, text: &str) -> std::io::Result<()> {
    write!(writer, "\x1b]52;c;{}\x07", STANDARD.encode(text))?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    #[test]
    fn copy_encodes_text_without_drawing_or_moving_the_cursor() {
        let mut output = Vec::new();
        super::write_osc52(&mut output, "one\ntwo").unwrap();
        assert_eq!(output, b"\x1b]52;c;b25lCnR3bw==\x07");
    }
}
