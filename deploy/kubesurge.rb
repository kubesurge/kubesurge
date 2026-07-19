class Kubesurge < Formula
  desc "Zero-touch live multi-cloud pod packet capture and diagnostics for Kubernetes"
  homepage "https://github.com/kubesurge/kubesurge"
  version "0.1.0" # Updated dynamically during release pipelines

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/kubesurge/kubesurge/releases/download/v#{version}/kubesurge_Darwin_x86_64.tar.gz"
      sha256 "replace-with-darwin-x86-sha"
    else
      url "https://github.com/kubesurge/kubesurge/releases/download/v#{version}/kubesurge_Darwin_arm64.tar.gz"
      sha256 "replace-with-darwin-arm-sha"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/kubesurge/kubesurge/releases/download/v#{version}/kubesurge_Linux_x86_64.tar.gz"
      sha256 "replace-with-linux-x86-sha"
    else
      url "https://github.com/kubesurge/kubesurge/releases/download/v#{version}/kubesurge_Linux_arm64.tar.gz"
      sha256 "replace-with-linux-arm-sha"
    end
  end

  def install
    bin.install "kubesurge"
    prefix.install_metafiles
  end

  test do
    system "#{bin}/kubesurge", "--version"
  end
end
