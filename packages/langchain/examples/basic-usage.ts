/**
 * Basic Usage Examples for @dupecom/botcha-langchain
 * 
 * These examples show how to use the LangChain integration.
 * Note: These are example code snippets - they require a real LangChain setup to run.
 */

import { BotchaTool, BotchaRequestWrapper } from '@dupecom/botcha-langchain';

// ============================================
// Example 1: Using BotchaTool with LangChain
// ============================================

async function exampleBotchaTool() {
  // Create the BOTCHA tool
  const botchaTool = new BotchaTool({
    baseUrl: 'https://api.botcha.ai',
    agentIdentity: 'MyAgent/1.0',
  });

  // Example 1a: Use directly to get a token
  const token = await botchaTool.getToken();
  console.log('Token obtained:', token.substring(0, 20) + '...');

  // Example 1b: Use in LangChain agent (requires @langchain/langgraph)
  /*
  import { ChatOpenAI } from '@langchain/openai';
  import { createReactAgent } from '@langchain/langgraph/prebuilt';

  const agent = createReactAgent({
    llm: new ChatOpenAI({ model: 'gpt-4' }),
    tools: [botchaTool],
  });

  const response = await agent.invoke({
    messages: [{ 
      role: 'user', 
      content: 'Get data from the BOTCHA-protected API at https://api.example.com/agent-only' 
    }]
  });
  */
}

// ============================================
// Example 2: Using BotchaRequestWrapper
// ============================================

async function exampleRequestWrapper() {
  // Create the wrapper
  const wrapper = new BotchaRequestWrapper({
    baseUrl: 'https://api.botcha.ai',
    agentIdentity: 'MyAgent/1.0',
  });

  // Example 2a: Fetch with automatic challenge solving
  try {
    const response = await wrapper.fetch('https://api.botcha.ai/agent-only');
    const data = await response.json();
    console.log('Response:', data);
  } catch (error) {
    console.error('Request failed:', error);
  }

  // Example 2b: Get token for manual use
  const token = await wrapper.getToken();
  console.log('Token for manual use:', token);

  // Example 2c: Create headers with challenge solution
  const headers = await wrapper.createHeaders();
  console.log('Headers:', headers);

  // Example 2d: Use token in custom request
  const manualResponse = await fetch('https://api.example.com/protected', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
}

// ============================================
// Example 3: Advanced Configuration
// ============================================

async function exampleAdvancedConfig() {
  // Configure with all options
  const tool = new BotchaTool({
    baseUrl: 'https://api.botcha.ai',
    agentIdentity: 'CustomAgent/2.0',
    maxRetries: 5,
    autoToken: true,
    name: 'custom_botcha_solver',
    description: 'Solves BOTCHA challenges for our specific use case',
  });

  const wrapper = new BotchaRequestWrapper({
    baseUrl: 'https://api.botcha.ai',
    agentIdentity: 'CustomAgent/2.0',
    maxRetries: 5,
    autoToken: true,
    fetchFn: fetch, // Can provide custom fetch implementation
  });

  // Clear cached token to force refresh
  tool.clearToken();
  wrapper.clearToken();
}

// Run examples (commented out - these require actual BOTCHA service)
// exampleBotchaTool().catch(console.error);
// exampleRequestWrapper().catch(console.error);
// exampleAdvancedConfig().catch(console.error);

export {
  exampleBotchaTool,
  exampleRequestWrapper,
  exampleAdvancedConfig,
};
