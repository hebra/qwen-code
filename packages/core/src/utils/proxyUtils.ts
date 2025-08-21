/**
 * @license
 * Copyright 2025 Qwen
 * SPDX-License-Identifier: Apache-2.0
 */

import { URL } from 'node:url';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { HttpProxyAgent } from 'http-proxy-agent';

/**
 * Parsed NO_PROXY pattern for efficient matching
 */
interface NoProxyPattern {
  type: 'domain' | 'ip' | 'cidr' | 'wildcard';
  pattern: string;
  port?: number;
  isSubdomain?: boolean;
}

/**
 * Cache for parsed NO_PROXY patterns to avoid re-parsing on every request
 */
let cachedNoProxyPatterns: NoProxyPattern[] | null = null;
let cachedNoProxyValue: string | null = null;

/**
 * Parse NO_PROXY environment variable into structured patterns
 * Supports: domains, subdomains, IPs, CIDR ranges, ports, wildcards
 */
export function parseNoProxy(noProxy: string): NoProxyPattern[] {
  if (!noProxy || noProxy.trim() === '') {
    return [];
  }

  const patterns: NoProxyPattern[] = [];
  const entries = noProxy.split(',').map(entry => entry.trim()).filter(Boolean);

  for (const entry of entries) {
    // Handle wildcard (no proxy for any host)
    if (entry === '*') {
      patterns.push({ type: 'wildcard', pattern: '*' });
      continue;
    }

    // Parse host:port format
    let host = entry;
    let port: number | undefined;
    
    const portMatch = entry.match(/^(.+):(\d+)$/);
    if (portMatch) {
      host = portMatch[1];
      port = parseInt(portMatch[2], 10);
    }

    // Determine pattern type
    if (host.includes('/')) {
      // CIDR notation (e.g., 192.168.0.0/16)
      patterns.push({ type: 'cidr', pattern: host, port });
    } else if (isIPAddress(host)) {
      // IP address
      patterns.push({ type: 'ip', pattern: host, port });
    } else {
      // Domain name
      const isSubdomain = host.startsWith('.');
      const isWildcard = host.startsWith('*.');
      
      if (isWildcard) {
        // Wildcard domain pattern (*.example.com)
        const cleanHost = host.substring(2); // Remove '*.'
        patterns.push({ 
          type: 'domain', 
          pattern: cleanHost.toLowerCase(), 
          port, 
          isSubdomain: true // Treat wildcard as subdomain match
        });
      } else {
        const cleanHost = isSubdomain ? host.substring(1) : host;
        patterns.push({ 
          type: 'domain', 
          pattern: cleanHost.toLowerCase(), 
          port, 
          isSubdomain 
        });
      }
    }
  }

  return patterns;
}

/**
 * Check if a string is an IP address (IPv4 or IPv6)
 */
function isIPAddress(host: string): boolean {
  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(host)) {
    const parts = host.split('.');
    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }

  // IPv6 pattern (simplified check)
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  return ipv6Pattern.test(host) || host === '::1' || host === '::';
}

/**
 * Check if an IP address matches a CIDR range
 */
function matchesCIDR(ip: string, cidr: string): boolean {
  try {
    const [network, prefixLength] = cidr.split('/');
    const prefix = parseInt(prefixLength, 10);
    
    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }

    // Convert IP addresses to 32-bit integers for comparison
    const ipToInt = (ipStr: string): number => {
      const parts = ipStr.split('.');
      if (parts.length !== 4) return 0;
      return parts.reduce((acc, part) => (acc << 8) + parseInt(part, 10), 0) >>> 0;
    };

    const ipInt = ipToInt(ip);
    const networkInt = ipToInt(network);
    const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;

    return (ipInt & mask) === (networkInt & mask);
  } catch {
    return false;
  }
}

/**
 * Check if a URL matches any NO_PROXY patterns
 */
export function matchesNoProxyPattern(url: string, patterns: NoProxyPattern[]): boolean {
  if (patterns.length === 0) {
    return false;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return false;
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : 
    (parsedUrl.protocol === 'https:' ? 443 : 80);

  for (const pattern of patterns) {
    // Wildcard matches everything
    if (pattern.type === 'wildcard') {
      return true;
    }

    // Check port if specified in pattern
    if (pattern.port !== undefined && pattern.port !== port) {
      continue;
    }

    switch (pattern.type) {
      case 'domain':
        if (pattern.isSubdomain) {
          // Subdomain pattern (.example.com matches sub.example.com)
          if (hostname === pattern.pattern || hostname.endsWith('.' + pattern.pattern)) {
            return true;
          }
        } else {
          // Exact domain match
          if (hostname === pattern.pattern) {
            return true;
          }
        }
        break;

      case 'ip':
        if (hostname === pattern.pattern) {
          return true;
        }
        break;

      case 'cidr':
        if (isIPAddress(hostname) && matchesCIDR(hostname, pattern.pattern)) {
          return true;
        }
        break;
    }
  }

  return false;
}

/**
 * Get cached NO_PROXY patterns or parse them if cache is invalid
 */
function getNoProxyPatterns(): NoProxyPattern[] {
  const currentNoProxy = process.env.NO_PROXY || process.env.no_proxy || '';
  
  // Return cached patterns if NO_PROXY hasn't changed
  if (cachedNoProxyPatterns && cachedNoProxyValue === currentNoProxy) {
    return cachedNoProxyPatterns;
  }

  // Parse and cache new patterns
  cachedNoProxyPatterns = parseNoProxy(currentNoProxy);
  cachedNoProxyValue = currentNoProxy;
  
  return cachedNoProxyPatterns;
}

/**
 * Check if a proxy should be used for the given URL
 * Returns false if the URL matches NO_PROXY patterns
 */
export function shouldUseProxy(targetUrl: string): boolean {
  const patterns = getNoProxyPatterns();
  return !matchesNoProxyPattern(targetUrl, patterns);
}

/**
 * Create an appropriate proxy agent for the given proxy URL and target URL
 * Returns undefined if no proxy should be used (respects NO_PROXY)
 */
export function createProxyAgent(proxyUrl: string, targetUrl: string): any {
  if (!proxyUrl || !shouldUseProxy(targetUrl)) {
    return undefined;
  }

  try {
    const parsedTarget = new URL(targetUrl);
    const isHttps = parsedTarget.protocol === 'https:';
    
    // Use HTTPS proxy agent for HTTPS targets, HTTP proxy agent for HTTP targets
    if (isHttps) {
      return new HttpsProxyAgent(proxyUrl);
    } else {
      return new HttpProxyAgent(proxyUrl);
    }
  } catch {
    // If URL parsing fails, don't use proxy
    return undefined;
  }
}

/**
 * Get proxy configuration for OpenAI SDK that respects NO_PROXY
 */
export function getOpenAIProxyConfig(proxyUrl: string | undefined, baseURL: string): { httpAgent?: any } {
  if (!proxyUrl) {
    return {};
  }

  const agent = createProxyAgent(proxyUrl, baseURL);
  return agent ? { httpAgent: agent } : {};
}

/**
 * Clear the NO_PROXY pattern cache (useful for testing)
 */
export function clearNoProxyCache(): void {
  cachedNoProxyPatterns = null;
  cachedNoProxyValue = null;
}
