require 'spec_helper'

describe MobileId::Cert do
  def cert(name)
    OpenSSL::X509::Certificate.new(File.read(File.join(described_class.root_path, name)))
  end

  describe '.live_store' do
    %w[
      EID-Q_2021E.pem.crt
      EID-Q_2021R.pem.crt
      EID-Q_2024E.pem.crt
      EID-Q_2024R.pem.crt
    ].each do |name|
      it "verifies the #{name} issuing CA" do
        described_class.live_store.verify(cert(name)).should == true
      end
    end
  end

  describe '.test_store' do
    %w[
      TEST_of_EID-Q_2021E.pem.crt
      TEST_of_EID-Q_2021R.pem.crt
      TEST_of_EID-Q_2024E.pem.crt
      TEST_of_EID-Q_2024R.pem.crt
    ].each do |name|
      it "verifies the #{name} issuing CA" do
        described_class.test_store.verify(cert(name)).should == true
      end
    end
  end

  describe 'bundled certificates' do
    it 'has no in-use CA expiring within 180 days' do
      now = Time.now
      soon = now + (180 * 24 * 60 * 60)

      expiry = Dir[File.join(described_class.root_path, '*.pem.crt')].map do |path|
        [File.basename(path), OpenSSL::X509::Certificate.new(File.read(path)).not_after]
      end

      expiring = expiry.select { |_name, not_after| not_after > now && not_after < soon }
      expiring.map(&:first).should == []
    end
  end
end
