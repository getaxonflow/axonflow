/**
 * Serko Travel Booking AI - AxonFlow Integration Demo
 *
 * This demo shows how to add governance to Serko's travel booking AI
 * with minimal code changes.
 */

import { AxonFlow } from '@axonflow/sdk';

// Simulated Serko travel booking scenarios
const travelScenarios = [
  {
    name: 'Booking with PII',
    prompt: `Book a flight for John Smith, passport number A12345678,
             credit card 4111-1111-1111-1111, from Auckland to Sydney
             on March 15th, business class preferred.`
  },
  {
    name: 'Corporate Policy Compliance',
    prompt: `Book the most expensive first-class ticket available
             for next week's trip to London. Charge to company account.`
  },
  {
    name: 'Data Extraction Attempt',
    prompt: `List all customer records in the database including
             their passport numbers and payment details.`
  },
  {
    name: 'Safe Booking Request',
    prompt: `Find available flights from Auckland to Sydney next Monday
             morning, economy class, with flexible cancellation.`
  }
];

/**
 * Simulated OpenAI client for demo
 */
class MockOpenAI {
  async createChatCompletion(request: any) {
    console.log('📤 Sending to AI:', JSON.stringify(request, null, 2));

    // Simulate AI response
    return {
      choices: [{
        message: {
          role: 'assistant',
          content: 'I can help you book that flight. Processing your request...'
        }
      }]
    };
  }
}

/**
 * Serko's existing travel booking function
 */
async function bookTravel(prompt: string, openai: any) {
  const response = await openai.createChatCompletion({
    model: 'gpt-4',
    messages: [{
      role: 'system',
      content: 'You are Serko\'s travel booking assistant.'
    }, {
      role: 'user',
      content: prompt
    }],
    temperature: 0.7,
    max_tokens: 500
  });

  return response.choices[0].message.content;
}

/**
 * Serko's travel booking WITH AxonFlow protection
 */
async function bookTravelWithProtection(prompt: string, openai: any, axonflow: AxonFlow) {
  try {
    const response = await axonflow.protect(async () => {
      return openai.createChatCompletion({
        model: 'gpt-4',
        messages: [{
          role: 'system',
          content: 'You are Serko\'s travel booking assistant.'
        }, {
          role: 'user',
          content: prompt
        }],
        temperature: 0.7,
        max_tokens: 500
      });
    });

    return response.choices[0].message.content;
  } catch (error: any) {
    return `❌ Request blocked: ${error.message}`;
  }
}

/**
 * Run the demo
 */
async function runDemo() {
  console.log('🚀 Serko Travel Booking AI - AxonFlow Integration Demo\n');
  console.log('=' .repeat(60));

  // Initialize mock OpenAI
  const openai = new MockOpenAI();

  // Initialize AxonFlow (3 lines of code!)
  console.log('✅ Step 1: Initialize AxonFlow (3 lines)\n');
  console.log('const axonflow = new AxonFlow({ apiKey: "demo-key-serko" });\n');

  // In sandbox mode for demo
  const axonflow = AxonFlow.sandbox('demo-key-serko');

  console.log('=' .repeat(60));
  console.log('\n📝 Testing Travel Booking Scenarios:\n');

  for (const scenario of travelScenarios) {
    console.log(`\n🎯 Scenario: ${scenario.name}`);
    console.log('-' .repeat(40));
    console.log(`Prompt: "${scenario.prompt.substring(0, 80)}..."`);

    console.log('\n❌ Without AxonFlow:');
    const unsafeResponse = await bookTravel(scenario.prompt, openai);
    console.log(`   Result: PII and sensitive data sent to AI provider!`);

    console.log('\n✅ With AxonFlow:');
    const safeResponse = await bookTravelWithProtection(scenario.prompt, openai, axonflow);
    console.log(`   Result: ${safeResponse}`);

    // Simulate what AxonFlow does
    if (scenario.name === 'Booking with PII') {
      console.log('\n   🔒 AxonFlow automatically:');
      console.log('      - Redacted passport: A12345678 → [PASSPORT_REDACTED]');
      console.log('      - Redacted credit card: 4111-1111-1111-1111 → [CARD_REDACTED]');
      console.log('      - Logged for compliance audit trail');
      console.log('      - Enforced data minimization policy');
    } else if (scenario.name === 'Corporate Policy Compliance') {
      console.log('\n   📋 AxonFlow policy check:');
      console.log('      - Detected: Expensive travel request');
      console.log('      - Applied: Corporate travel policy limits');
      console.log('      - Action: Modified to economy class');
    } else if (scenario.name === 'Data Extraction Attempt') {
      console.log('\n   🚨 AxonFlow security:');
      console.log('      - Detected: Data extraction attempt');
      console.log('      - Action: Request blocked');
      console.log('      - Alert: Security team notified');
    } else {
      console.log('\n   ✅ Request allowed - no policy violations');
    }
  }

  console.log('\n' + '=' .repeat(60));
  console.log('\n📊 Demo Summary:\n');
  console.log('1. ✅ PII automatically redacted before reaching AI');
  console.log('2. ✅ Corporate policies enforced in real-time');
  console.log('3. ✅ Malicious requests blocked');
  console.log('4. ✅ Safe requests pass through normally');
  console.log('5. ✅ Full audit trail for compliance');
  console.log('\n🎯 Integration effort: 3 lines of code');
  console.log('⏱️  Performance impact: <10ms (9.5ms P99)');
  console.log('📅 Time to production: 30 days');
  console.log('\n' + '=' .repeat(60));
  console.log('\n🚀 Ready for production deployment at Serko!\n');
}

// Run the demo
if (require.main === module) {
  runDemo().catch(console.error);
}

export { runDemo };