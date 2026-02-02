/**
 * Tests for BotchaTool
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { BotchaTool } from '../src/tool.js';
import { BotchaClient } from '@dupecom/botcha/client';

// Mock BotchaClient
vi.mock('@dupecom/botcha/client', () => {
  const MockBotchaClient = vi.fn(function(this: any) {
    this.getToken = vi.fn().mockResolvedValue('mock-jwt-token-1234567890abcdef');
    this.clearToken = vi.fn();
    return this;
  });
  
  return {
    BotchaClient: MockBotchaClient,
  };
});

describe('BotchaTool', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create a tool with default name and description', () => {
    const tool = new BotchaTool();
    
    expect(tool.name).toBe('botcha_solver');
    expect(tool.description).toContain('BOTCHA');
    expect(tool.description).toContain('token');
  });

  it('should create a tool with custom name and description', () => {
    const tool = new BotchaTool({
      name: 'custom_botcha',
      description: 'Custom BOTCHA solver',
    });
    
    expect(tool.name).toBe('custom_botcha');
    expect(tool.description).toBe('Custom BOTCHA solver');
  });

  it('should have correct schema for input', () => {
    const tool = new BotchaTool();
    
    // The schema should accept { action: 'getToken' }
    const result = tool.schema.safeParse({ action: 'getToken' });
    expect(result.success).toBe(true);
  });

  it('should reject invalid action in schema', () => {
    const tool = new BotchaTool();
    
    // The schema should reject other actions
    const result = tool.schema.safeParse({ action: 'invalid' });
    expect(result.success).toBe(false);
  });

  it('should call getToken and return formatted token', async () => {
    const tool = new BotchaTool({ baseUrl: 'https://api.botcha.ai' });
    
    const result = await tool.invoke({ action: 'getToken' });
    
    expect(result).toContain('Successfully obtained BOTCHA token');
    expect(result).toContain('mock-jwt-token');
    expect(result).toContain('Authorization: Bearer');
  });

  it('should provide direct getToken method', async () => {
    const tool = new BotchaTool();
    
    const token = await tool.getToken();
    
    expect(token).toBe('mock-jwt-token-1234567890abcdef');
  });

  it('should provide clearToken method', () => {
    const tool = new BotchaTool();
    
    tool.clearToken();
    
    // Verify that clearToken was called on the client
    const mockClient = vi.mocked(BotchaClient).mock.results[0].value;
    expect(mockClient.clearToken).toHaveBeenCalled();
  });

  it('should handle errors gracefully', async () => {
    // Create a tool with a client that throws an error
    vi.mocked(BotchaClient).mockImplementationOnce(function(this: any) {
      this.getToken = vi.fn().mockRejectedValue(new Error('Network error'));
      this.clearToken = vi.fn();
      return this;
    } as any);

    const tool = new BotchaTool();
    const result = await tool.invoke({ action: 'getToken' });
    
    expect(result).toContain('Failed to solve BOTCHA challenge');
    expect(result).toContain('Network error');
  });

  it('should pass options to BotchaClient', () => {
    new BotchaTool({
      baseUrl: 'https://custom.botcha.ai',
      agentIdentity: 'TestAgent/1.0',
      maxRetries: 5,
      autoToken: false,
    });

    expect(BotchaClient).toHaveBeenCalledWith({
      baseUrl: 'https://custom.botcha.ai',
      agentIdentity: 'TestAgent/1.0',
      maxRetries: 5,
      autoToken: false,
    });
  });
});
