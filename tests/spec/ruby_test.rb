#! /usr/bin/env rspec

require "spec_helper"
require "twopence"
require "fileutils"

describe Twopence::Target do
  before :all do
    @target = Twopence::init( ENV["TARGET"] )
    trap("INT") { @target.interrupt_command(); exit() }
  end

  describe "#test_and_store_results_together" do
    it "runs a remote command by default as root" do
      out, rc, major, minor = @target.test_and_store_results_together('whoami')
      expect(rc).to eq(0); expect(major).to eq(0); expect(minor).to eq(0)
      expect(out).to eq("root\n")
    end

    it "can run a remote command as a different user" do
      out, rc, major, minor = @target.test_and_store_results_together('whoami', 'nobody')
      expect(rc).to eq(0); expect(major).to eq(0); expect(minor).to eq(0)
      expect(out).to eq("nobody\n")
    end

    it "stores stderr in the common buffer" do
      out, rc, major, minor = @target.test_and_store_results_together('echo good; echo bad >&2; echo good again')
      expect(rc).to eq(0); expect(major).to eq(0); expect(minor).to eq(0)
      expect(out).to eq("good\nbad\ngood again\n")
    end

    it "can take its input from a file" do
      old_stdin = $stdin.dup
      new_stdin = File::open('/etc/hosts', 'r')
      $stdin.reopen(new_stdin)
      out, rc, major, minor = @target.test_and_store_results_together('cat')
      $stdin.reopen(old_stdin)
      expect(rc).to eq(0); expect(major).to eq(0); expect(minor).to eq(0)
      #
      local_file = File::open('/etc/hosts', 'r')
      out2 = local_file.read
      expect(out).to eq(out2)
    end
  end

  describe "#test_and_drop_results" do
    it "detects failing commands" do
      rc, major, minor = @target.test_and_drop_results('/bin/ooops')
      expect(rc).to eq(0); expect(major).to eq(0); expect(minor).to eq(127)
      #
      rc, major, minor = @target.test_and_drop_results('ls /bin/ooops')
      expect(rc).to eq(0); expect(major).to eq(0); expect(minor).to eq(2)
      #
      rc, major, minor = @target.test_and_drop_results('bash -c "kill -9 $$"')
      expect(rc).to eq(0); expect(major).to eq(9); expect(minor).to eq(0)
    end
  end

  describe "#test_and_store_results_separately" do
    it "stores stdout and stderr in different buffers" do
      out, err, rc, major, minor = @target.test_and_store_results_separately('echo good; echo bad >&2; echo good again')
      expect(rc).to eq(0); expect(major).to eq(0); expect(minor).to eq(0)
      expect(out).to eq("good\ngood again\n")
      expect(err).to eq("bad\n")
    end
  end

  describe "#inject_file" do
    it "injects a file" do
      rc, remote_rc = @target.inject_file('/etc/hosts', '/tmp/injected')
      expect(rc).to eq(0); expect(remote_rc).to eq(0)
    end
  end

  describe "#extract_file" do
    it "extracts injected file again" do
      rc, remote_rc = @target.extract_file('/tmp/injected', 'etc_hosts')
      expect(rc).to eq(0); expect(remote_rc).to eq(0)
      #
      expect(FileUtils.compare_file('/etc/hosts', 'etc_hosts')).to be(true)
      FileUtils.rm('etc_hosts')
    end
  end
end
