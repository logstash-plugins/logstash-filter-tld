require 'logstash/devutils/rspec/spec_helper'
require 'logstash/filters/tld'

describe LogStash::Filters::Tld do
  let(:config) { {} }

  subject(:plugin) { described_class.new(config) }

  let(:event) { LogStash::Event.new('message' => 'www.google.com') }

  before(:each) { plugin.register }

  shared_examples 'sets tld fields' do |source, target|
    let(:config) { {'source' => source, 'target' => target } }

    context 'domain without subdomains' do
      it 'should set tld fields' do
        expect_tld_event_fields(target, LogStash::Event.new(source => 'google.com'), {
                                  'tld' => 'com',
                                  'top_level_domain' => 'com',
                                  'sld' => 'google',
                                  'trd' => nil,
                                  'domain' => 'google.com',
                                  'subdomain' => nil
                                })

        expect_tld_event_fields(target, LogStash::Event.new(source => 'google.co.uk'), {
                                  'tld' => 'co.uk',
                                  'top_level_domain' => 'co.uk',
                                  'sld' => 'google',
                                  'trd' => nil,
                                  'domain' => 'google.co.uk',
                                  'subdomain' => nil
                                })
      end
    end

    context 'domain with subdomains' do
      it 'should set tld fields' do
        expect_tld_event_fields(target, LogStash::Event.new(source => 'www.google.com'), {
                                  'tld' => 'com',
                                  'top_level_domain' => 'com',
                                  'sld' => 'google',
                                  'trd' => 'www',
                                  'domain' => 'google.com',
                                  'subdomain' => 'www.google.com'
                                })

        expect_tld_event_fields(target, LogStash::Event.new(source => 'foo.bar.google.es'), {
                                  'tld' => 'es',
                                  'top_level_domain' => 'es',
                                  'sld' => 'google',
                                  'trd' => 'foo.bar',
                                  'domain' => 'google.es',
                                  'subdomain' => 'foo.bar.google.es'
                                })
      end
    end
  end

  context 'with default configuration' do
    include_examples('sets tld fields', 'message', 'tld')
  end

  context 'with `source` option configured' do
    include_examples('sets tld fields', 'another_source', 'tld')
  end

  context 'with `target` option configured' do
    include_examples('sets tld fields', 'message', 'another_tld')
  end

  context 'with `source` and `target` options configured' do
    include_examples('sets tld fields', 'another_source', 'another_tld')
  end

  private

  def expect_tld_event_fields(target, event, hash)
    subject.filter(event)
    hash.each do |key, value|
      expect(event.get(target)[key]).to eq(value)
    end
  end
end
