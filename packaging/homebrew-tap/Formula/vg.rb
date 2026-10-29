# Homebrew formula for vg (the @vibgrate/cli package).
# The release pipeline stamps url version + sha256 from the npm tarball.
class Vg < Formula
  desc "Deterministic, no-API-key code graph for AI assistants (vg)"
  homepage "https://vibgrate.com"
  url "https://registry.npmjs.org/@vibgrate/cli/-/cli-2026.1029.1.tgz"
  sha256 "7a4873090b2aa3e36fd2f355f60a8b959f63d2d2d96f6da051b47c77019c9414"
  license "Apache-2.0"
  depends_on "node"

  def install
    # Install from the tarball Homebrew already downloaded and checksum-verified
    # (staged into buildpath) — never a second, unverified registry fetch.
    system "npm", "install", *std_npm_args
    bin.install_symlink Dir["#{libexec}/bin/vg"]
    bin.install_symlink Dir["#{libexec}/bin/vibgrate"]
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vg --version")
  end
end
