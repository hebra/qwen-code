/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  parseNoProxy,
  matchesNoProxyPattern,
  shouldUseProxy,
  createProxyAgent,
  getOpenAIProxyConfig,
  clearNoProxyCache,
} from './proxyUtils.js';

describe('proxyUtils', () => {
  beforeEach(() => {
    // Clear cache and environment variables before each test
    clearNoProxyCache();
    delete process.env.NO_PROXY;
    delete process.env.no_proxy;
  });

  afterEach(() => {
    // Clean up after each test
    clearNoProxyCache();
    delete process.env.NO_PROXY;
    delete process.env.no_proxy;
  });

  describe('parseNoProxy', () => {
    it('should return empty array for empty input', () => {
      expect(parseNoProxy('')).toEqual([]);
      expect(parseNoProxy('   ')).toEqual([]);
    });

    it('should parse wildcard pattern', () => {
      const patterns = parseNoProxy('*');
      expect(patterns).toEqual([
        { type: 'wildcard', pattern: '*' }
      ]);
    });

    it('should parse wildcard domain patterns', () => {
      const patterns = parseNoProxy('*.example.com,*.test.org');
      expect(patterns).toEqual([
        { type: 'domain', pattern: 'example.com', isSubdomain: true },
        { type: 'domain', pattern: 'test.org', isSubdomain: true }
      ]);
    });

    it('should parse domain patterns', () => {
      const patterns = parseNoProxy('example.com,test.org');
      expect(patterns).toEqual([
        { type: 'domain', pattern: 'example.com', isSubdomain: false },
        { type: 'domain', pattern: 'test.org', isSubdomain: false }
      ]);
    });

    it('should parse subdomain patterns', () => {
      const patterns = parseNoProxy('.example.com,.test.org');
      expect(patterns).toEqual([
        { type: 'domain', pattern: 'example.com', isSubdomain: true },
        { type: 'domain', pattern: 'test.org', isSubdomain: true }
      ]);
    });

    it('should parse IP address patterns', () => {
      const patterns = parseNoProxy('192.168.1.1,10.0.0.1');
      expect(patterns).toEqual([
        { type: 'ip', pattern: '192.168.1.1' },
        { type: 'ip', pattern: '10.0.0.1' }
      ]);
    });

    it('should parse CIDR patterns', () => {
      const patterns = parseNoProxy('192.168.0.0/16,10.0.0.0/8');
      expect(patterns).toEqual([
        { type: 'cidr', pattern: '192.168.0.0/16' },
        { type: 'cidr', pattern: '10.0.0.0/8' }
      ]);
    });

    it('should parse patterns with ports', () => {
      const patterns = parseNoProxy('example.com:8080,192.168.1.1:3128');
      expect(patterns).toEqual([
        { type: 'domain', pattern: 'example.com', port: 8080, isSubdomain: false },
        { type: 'ip', pattern: '192.168.1.1', port: 3128 }
      ]);
    });

    it('should handle mixed patterns', () => {
      const patterns = parseNoProxy('example.com,.test.org,192.168.1.1,10.0.0.0/8,localhost:8080');
      expect(patterns).toHaveLength(5);
      expect(patterns[0]).toEqual({ type: 'domain', pattern: 'example.com', isSubdomain: false });
      expect(patterns[1]).toEqual({ type: 'domain', pattern: 'test.org', isSubdomain: true });
      expect(patterns[2]).toEqual({ type: 'ip', pattern: '192.168.1.1' });
      expect(patterns[3]).toEqual({ type: 'cidr', pattern: '10.0.0.0/8' });
      expect(patterns[4]).toEqual({ type: 'domain', pattern: 'localhost', port: 8080, isSubdomain: false });
    });

    it('should handle whitespace and empty entries', () => {
      const patterns = parseNoProxy(' example.com , , test.org , ');
      expect(patterns).toEqual([
        { type: 'domain', pattern: 'example.com', isSubdomain: false },
        { type: 'domain', pattern: 'test.org', isSubdomain: false }
      ]);
    });
  });

  describe('matchesNoProxyPattern', () => {
    it('should return false for empty patterns', () => {
      expect(matchesNoProxyPattern('https://example.com', [])).toBe(false);
    });

    it('should match wildcard pattern', () => {
      const patterns = parseNoProxy('*');
      expect(matchesNoProxyPattern('https://example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('http://test.org', patterns)).toBe(true);
    });

    it('should match exact domain', () => {
      const patterns = parseNoProxy('example.com');
      expect(matchesNoProxyPattern('https://example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('http://example.com:8080', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://test.com', patterns)).toBe(false);
    });

    it('should match subdomain patterns', () => {
      const patterns = parseNoProxy('.example.com');
      expect(matchesNoProxyPattern('https://sub.example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://deep.sub.example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://notexample.com', patterns)).toBe(false);
    });

    it('should match wildcard domain patterns', () => {
      const patterns = parseNoProxy('*.example.com');
      expect(matchesNoProxyPattern('https://api.example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://sub.example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://deep.sub.example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://notexample.com', patterns)).toBe(false);
    });

    it('should match IP addresses', () => {
      const patterns = parseNoProxy('192.168.1.1');
      expect(matchesNoProxyPattern('https://192.168.1.1', patterns)).toBe(true);
      expect(matchesNoProxyPattern('http://192.168.1.1:8080', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://192.168.1.2', patterns)).toBe(false);
    });

    it('should match CIDR ranges', () => {
      const patterns = parseNoProxy('192.168.0.0/16');
      expect(matchesNoProxyPattern('https://192.168.1.1', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://192.168.255.255', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://192.169.1.1', patterns)).toBe(false);
      expect(matchesNoProxyPattern('https://10.0.0.1', patterns)).toBe(false);
    });

    it('should match specific ports', () => {
      const patterns = parseNoProxy('example.com:8080');
      expect(matchesNoProxyPattern('https://example.com:8080', patterns)).toBe(true);
      expect(matchesNoProxyPattern('http://example.com:8080', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://example.com:443', patterns)).toBe(false);
      expect(matchesNoProxyPattern('https://example.com', patterns)).toBe(false); // default port 443
    });

    it('should handle default ports correctly', () => {
      const patterns = parseNoProxy('example.com:443,test.com:80');
      expect(matchesNoProxyPattern('https://example.com', patterns)).toBe(true); // default HTTPS port
      expect(matchesNoProxyPattern('http://test.com', patterns)).toBe(true); // default HTTP port
      expect(matchesNoProxyPattern('https://test.com', patterns)).toBe(false); // wrong port
    });

    it('should handle invalid URLs gracefully', () => {
      const patterns = parseNoProxy('example.com');
      expect(matchesNoProxyPattern('invalid-url', patterns)).toBe(false);
      expect(matchesNoProxyPattern('', patterns)).toBe(false);
    });

    it('should be case insensitive for hostnames', () => {
      const patterns = parseNoProxy('Example.COM');
      expect(matchesNoProxyPattern('https://example.com', patterns)).toBe(true);
      expect(matchesNoProxyPattern('https://EXAMPLE.COM', patterns)).toBe(true);
    });
  });

  describe('shouldUseProxy', () => {
    it('should return true when NO_PROXY is not set', () => {
      expect(shouldUseProxy('https://example.com')).toBe(true);
    });

    it('should return false when URL matches NO_PROXY', () => {
      process.env.NO_PROXY = 'example.com';
      expect(shouldUseProxy('https://example.com')).toBe(false);
    });

    it('should return true when URL does not match NO_PROXY', () => {
      process.env.NO_PROXY = 'example.com';
      expect(shouldUseProxy('https://test.com')).toBe(true);
    });

    it('should support both NO_PROXY and no_proxy environment variables', () => {
      process.env.no_proxy = 'example.com';
      expect(shouldUseProxy('https://example.com')).toBe(false);
      
      // NO_PROXY takes precedence
      process.env.NO_PROXY = 'test.com';
      expect(shouldUseProxy('https://example.com')).toBe(true);
      expect(shouldUseProxy('https://test.com')).toBe(false);
    });

    it('should cache patterns for performance', () => {
      process.env.NO_PROXY = 'example.com';
      
      // First call should parse and cache
      expect(shouldUseProxy('https://example.com')).toBe(false);
      
      // Second call should use cache
      expect(shouldUseProxy('https://test.com')).toBe(true);
      
      // Changing environment should invalidate cache
      process.env.NO_PROXY = 'test.com';
      expect(shouldUseProxy('https://example.com')).toBe(true);
      expect(shouldUseProxy('https://test.com')).toBe(false);
    });
  });

  describe('createProxyAgent', () => {
    it('should return undefined when no proxy URL provided', () => {
      const agent = createProxyAgent('', 'https://example.com');
      expect(agent).toBeUndefined();
    });

    it('should return undefined when target matches NO_PROXY', () => {
      process.env.NO_PROXY = 'example.com';
      const agent = createProxyAgent('http://proxy:8080', 'https://example.com');
      expect(agent).toBeUndefined();
    });

    it('should return HTTPS proxy agent for HTTPS targets', () => {
      const agent = createProxyAgent('http://proxy:8080', 'https://example.com');
      expect(agent).toBeDefined();
      expect(agent.constructor.name).toBe('HttpsProxyAgent');
    });

    it('should return HTTP proxy agent for HTTP targets', () => {
      const agent = createProxyAgent('http://proxy:8080', 'http://example.com');
      expect(agent).toBeDefined();
      expect(agent.constructor.name).toBe('HttpProxyAgent');
    });

    it('should handle invalid target URLs gracefully', () => {
      const agent = createProxyAgent('http://proxy:8080', 'invalid-url');
      expect(agent).toBeUndefined();
    });
  });

  describe('getOpenAIProxyConfig', () => {
    it('should return empty config when no proxy URL provided', () => {
      const config = getOpenAIProxyConfig(undefined, 'https://api.openai.com');
      expect(config).toEqual({});
    });

    it('should return empty config when target matches NO_PROXY', () => {
      process.env.NO_PROXY = 'api.openai.com';
      const config = getOpenAIProxyConfig('http://proxy:8080', 'https://api.openai.com');
      expect(config).toEqual({});
    });

    it('should return httpAgent config when proxy should be used', () => {
      const config = getOpenAIProxyConfig('http://proxy:8080', 'https://api.openai.com');
      expect(config).toHaveProperty('httpAgent');
      expect(config.httpAgent).toBeDefined();
    });
  });

  describe('real-world NO_PROXY scenarios', () => {
    it('should handle common corporate proxy bypass patterns', () => {
      process.env.NO_PROXY = 'localhost,127.0.0.1,.local,.internal,10.0.0.0/8,192.168.0.0/16';
      
      // Should bypass proxy
      expect(shouldUseProxy('http://localhost:3000')).toBe(false);
      expect(shouldUseProxy('https://127.0.0.1:8080')).toBe(false);
      expect(shouldUseProxy('https://app.local')).toBe(false);
      expect(shouldUseProxy('https://service.internal')).toBe(false);
      expect(shouldUseProxy('https://10.1.2.3')).toBe(false);
      expect(shouldUseProxy('https://192.168.1.100')).toBe(false);
      
      // Should use proxy
      expect(shouldUseProxy('https://api.openai.com')).toBe(true);
      expect(shouldUseProxy('https://github.com')).toBe(true);
    });

    it('should handle OpenAI and similar API endpoints', () => {
      process.env.NO_PROXY = 'api.openai.com,openrouter.ai,dashscope.aliyuncs.com';
      
      expect(shouldUseProxy('https://api.openai.com/v1/chat/completions')).toBe(false);
      expect(shouldUseProxy('https://openrouter.ai/api/v1/chat/completions')).toBe(false);
      expect(shouldUseProxy('https://dashscope.aliyuncs.com/compatible-mode/v1')).toBe(false);
      expect(shouldUseProxy('https://api.anthropic.com')).toBe(true);
    });

    it('should handle wildcard bypass', () => {
      process.env.NO_PROXY = '*';
      
      expect(shouldUseProxy('https://api.openai.com')).toBe(false);
      expect(shouldUseProxy('https://github.com')).toBe(false);
      expect(shouldUseProxy('http://localhost:3000')).toBe(false);
    });
  });
});
