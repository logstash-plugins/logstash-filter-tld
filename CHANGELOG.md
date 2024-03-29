## 3.1.3
  - Bumped `public_suffix` gem version to `> 4` `< 6` and updated specs [#24](https://github.com/logstash-plugins/logstash-filter-tld/issues/24)

## 3.1.2
  - Fix race condition initializing PublicSuffix list [#8](https://github.com/logstash-plugins/logstash-filter-tld/issues/8)

## 3.1.1
  - Honor ECS and add top_level_domain

## 3.0.3
  - Update gemspec summary

## 3.0.2
  - Fix some documentation issues

## 3.0.0
  - Breaking: Updated plugin to use new Java Event APIs
  - relax logstash-core-plugin-api constrains
  - update .travis.yml

# 2.0.4
  - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 2.0.3
  - New dependency requirements for logstash-core for the 5.0 release
## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

