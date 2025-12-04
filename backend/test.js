/**
 * Script de test de sécurité pour EventHub Backend
 * Usage: node test-security.js
 */

const http = require('http');
const https = require('https');

// Configuration
const BASE_URL = process.env.API_URL || 'http://localhost:3000';
const VERBOSE = process.env.VERBOSE === 'true';

// Couleurs pour la console
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

let passedTests = 0;
let failedTests = 0;
let warnings = 0;

// Helper pour faire des requêtes HTTP
function makeRequest(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const client = url.protocol === 'https:' ? https : http;
    
    const reqOptions = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    };

    const req = client.request(reqOptions, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ status: res.statusCode, data: parsed, headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, data: data, headers: res.headers });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (options.body) {
      req.write(JSON.stringify(options.body));
    }

    req.end();
  });
}

// Helpers de test
function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logTest(name, passed, details = '') {
  if (passed) {
    passedTests++;
    log(`  ✓ ${name}`, 'green');
  } else {
    failedTests++;
    log(`  ✗ ${name}`, 'red');
  }
  if (details && (VERBOSE || !passed)) {
    log(`    ${details}`, 'yellow');
  }
}

function logWarning(message) {
  warnings++;
  log(`  ⚠ ${message}`, 'yellow');
}

function logSection(title) {
  log(`\n${'='.repeat(60)}`, 'cyan');
  log(title, 'cyan');
  log('='.repeat(60), 'cyan');
}

// Tests
async function testHealthCheck() {
  logSection('TEST 1: Health Check');
  
  try {
    const response = await makeRequest('/api/health');
    
    logTest(
      'API est accessible',
      response.status === 200,
      `Status: ${response.status}`
    );
    
    logTest(
      'Réponse contient success=true',
      response.data.success === true,
      `Success: ${response.data.success}`
    );
    
    logTest(
      'Réponse contient timestamp',
      !!response.data.timestamp,
      `Timestamp: ${response.data.timestamp}`
    );
    
    logTest(
      'Réponse contient environment',
      !!response.data.environment,
      `Environment: ${response.data.environment}`
    );
    
    if (response.data.environment === 'production' && BASE_URL.includes('localhost')) {
      logWarning('Environnement en production mais URL est localhost');
    }
    
  } catch (error) {
    logTest('API est accessible', false, error.message);
  }
}

async function testSecurityHeaders() {
  logSection('TEST 2: Headers de Sécurité (Helmet)');
  
  try {
    const response = await makeRequest('/api/health');
    const headers = response.headers;
    
    logTest(
      'X-Content-Type-Options présent',
      headers['x-content-type-options'] === 'nosniff',
      `Valeur: ${headers['x-content-type-options']}`
    );
    
    logTest(
      'X-Frame-Options présent',
      !!headers['x-frame-options'],
      `Valeur: ${headers['x-frame-options']}`
    );
    
    logTest(
      'X-XSS-Protection présent',
      !!headers['x-xss-protection'],
      `Valeur: ${headers['x-xss-protection']}`
    );
    
    logTest(
      'Strict-Transport-Security présent',
      !!headers['strict-transport-security'],
      `Valeur: ${headers['strict-transport-security']}`
    );
    
    if (!headers['strict-transport-security'] && BASE_URL.startsWith('https')) {
      logWarning('HSTS devrait être configuré pour HTTPS');
    }
    
  } catch (error) {
    logTest('Headers de sécurité', false, error.message);
  }
}

async function testRateLimiting() {
  logSection('TEST 3: Rate Limiting');
  
  try {
    log('  Envoi de 10 requêtes rapides...');
    const requests = [];
    
    for (let i = 0; i < 10; i++) {
      requests.push(makeRequest('/api/health'));
    }
    
    const responses = await Promise.all(requests);
    const success = responses.filter(r => r.status === 200).length;
    
    logTest(
      'Rate limiting actif (certaines requêtes passent)',
      success > 0,
      `${success}/10 requêtes réussies`
    );
    
    log('\n  Test rate limiting authentification (5 tentatives échouées)...');
    const loginAttempts = [];
    
    for (let i = 0; i < 6; i++) {
      loginAttempts.push(
        makeRequest('/api/auth/login', {
          method: 'POST',
          body: {
            email: 'test@invalide.com',
            password: 'wrongpassword'
          }
        })
      );
    }
    
    const loginResponses = await Promise.all(loginAttempts);
    const tooManyRequests = loginResponses.some(r => r.status === 429);
    
    logTest(
      'Rate limiting login actif (bloque après 5 tentatives)',
      tooManyRequests,
      tooManyRequests ? 'Bloqué après plusieurs tentatives' : 'Aucun blocage détecté'
    );
    
  } catch (error) {
    logTest('Rate limiting', false, error.message);
  }
}

async function testInputValidation() {
  logSection('TEST 4: Validation des Entrées');
  
  try {
    // Test email invalide
    const invalidEmail = await makeRequest('/api/auth/register', {
      method: 'POST',
      body: {
        firstName: 'Test',
        lastName: 'User',
        email: 'invalid-email',
        phone: '+33612345678',
        school: 'Test School',
        password: 'TestPassword123!'
      }
    });
    
    logTest(
      'Rejette email invalide',
      invalidEmail.status === 400,
      `Status: ${invalidEmail.status}`
    );
    
    // Test mot de passe court
    const shortPassword = await makeRequest('/api/auth/register', {
      method: 'POST',
      body: {
        firstName: 'Test',
        lastName: 'User',
        email: 'test@valid.com',
        phone: '+33612345678',
        school: 'Test School',
        password: 'short'
      }
    });
    
    logTest(
      'Rejette mot de passe trop court',
      shortPassword.status === 400,
      `Status: ${shortPassword.status}`
    );
    
    // Test champs manquants
    const missingFields = await makeRequest('/api/auth/register', {
      method: 'POST',
      body: {
        email: 'test@valid.com',
        password: 'TestPassword123!'
      }
    });
    
    logTest(
      'Rejette champs manquants',
      missingFields.status === 400,
      `Status: ${missingFields.status}`
    );
    
  } catch (error) {
    logTest('Validation des entrées', false, error.message);
  }
}

async function testAuthenticationFlow() {
  logSection('TEST 5: Flux d\'Authentification');
  
  const testUser = {
    firstName: 'Security',
    lastName: 'Test',
    email: `test-${Date.now()}@security.test`,
    phone: '+33612345678',
    school: 'Security Test School',
    password: 'SecurePassword123!'
  };
  
  try {
    // Test inscription
    const register = await makeRequest('/api/auth/register', {
      method: 'POST',
      body: testUser
    });
    
    logTest(
      'Inscription réussie',
      register.status === 201 && register.data.success,
      `Status: ${register.status}`
    );
    
    logTest(
      'Retourne accessToken',
      !!register.data.data?.accessToken,
      register.data.data?.accessToken ? 'Token présent' : 'Token absent'
    );
        
    if (!register.data.data?.accessToken) {
      logWarning('Le système de refresh tokens n\'est peut-être pas configuré');
      return;
    }
    
    const accessToken = register.data.data.accessToken;
    const refreshToken = register.data.data.refreshToken;
    
    // Test route protégée avec token
    const profile = await makeRequest('/api/user/profile', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    
    logTest(
      'Accès route protégée avec token',
      profile.status === 200,
      `Status: ${profile.status}`
    );
    
    // Test route protégée sans token
    const noAuth = await makeRequest('/api/user/profile', {
      method: 'GET'
    });
    
    logTest(
      'Bloque accès sans token',
      noAuth.status === 401,
      `Status: ${noAuth.status}`
    );
      
    const login = await makeRequest('/api/auth/login', {
      method: 'POST',
      body: {
        email: testUser.email,
        password: testUser.password
      }
    });
    
    logTest(
      'Connexion réussie 222',
      login.status === 200,
      `Status: ${login.status}`
    );
        
  } catch (error) {
    logTest('Flux d\'authentification', false, error.message);
  }
}

async function testSQLInjectionProtection() {
  logSection('TEST 6: Protection contre Injection SQL');
  
  try {
    const maliciousInputs = [
      "admin'--",
      "1' OR '1'='1",
      "'; DROP TABLE users--",
      "admin' OR 1=1--",
      "' UNION SELECT * FROM users--"
    ];
    
    let allBlocked = true;
    
    for (const input of maliciousInputs) {
      const response = await makeRequest('/api/auth/login', {
        method: 'POST',
        body: {
          email: input,
          password: 'password'
        }
      });
      
      // Devrait retourner 400 (validation) ou 401 (auth failed), pas 500 (erreur SQL)
      if (response.status === 500) {
        allBlocked = false;
        if (VERBOSE) {
          log(`    ⚠ Input "${input}" a causé une erreur 500`, 'yellow');
        }
      }
    }
    
    logTest(
      'Bloque tentatives d\'injection SQL',
      allBlocked,
      allBlocked ? 'Toutes les tentatives bloquées' : 'Certaines tentatives ont causé des erreurs'
    );
    
  } catch (error) {
    logTest('Protection SQL Injection', false, error.message);
  }
}

async function testXSSProtection() {
  logSection('TEST 7: Protection contre XSS');
  
  try {
    const xssPayloads = [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg onload=alert('XSS')>"
    ];
    
    let allSanitized = true;
    
    for (const payload of xssPayloads) {
      const response = await makeRequest('/api/auth/register', {
        method: 'POST',
        body: {
          firstName: payload,
          lastName: 'Test',
          email: `test-${Date.now()}@xss.test`,
          phone: '+33612345678',
          school: 'Test',
          password: 'TestPassword123!'
        }
      });
      
      // Devrait soit rejeter (400) soit sanitiser
      if (response.status === 201 && response.data.data?.user?.firstName === payload) {
        allSanitized = false;
        if (VERBOSE) {
          log(`    ⚠ Payload "${payload}" n'a pas été sanitisé`, 'yellow');
        }
      }
    }
    
    logTest(
      'Sanitise ou bloque payloads XSS',
      allSanitized,
      allSanitized ? 'Tous les payloads traités' : 'Certains payloads non sanitisés'
    );
    
  } catch (error) {
    logTest('Protection XSS', false, error.message);
  }
}

async function testCORS() {
  logSection('TEST 8: Configuration CORS');
  
  try {
    const response = await makeRequest('/api/health', {
      headers: {
        'Origin': 'http://malicious-site.com'
      }
    });
    
    const corsHeader = response.headers['access-control-allow-origin'];
    
    logTest(
      'CORS configuré',
      !!corsHeader,
      `Access-Control-Allow-Origin: ${corsHeader || 'Non défini'}`
    );
    
    if (corsHeader === '*') {
      logWarning('CORS accepte toutes les origines (non recommandé en production)');
    } else {
      log(`  ℹ CORS restreint à: ${corsHeader}`, 'blue');
    }
    
  } catch (error) {
    logTest('Configuration CORS', false, error.message);
  }
}

async function testErrorHandling() {
  logSection('TEST 9: Gestion des Erreurs');
  
  try {
    // Route inexistante
    const notFound = await makeRequest('/api/route-qui-nexiste-pas');
    
    logTest(
      'Retourne 404 pour routes inexistantes',
      notFound.status === 404,
      `Status: ${notFound.status}`
    );
    
    logTest(
      'Erreur 404 ne révèle pas d\'info sensible',
      !notFound.data.stack && !notFound.data.error?.stack,
      'Pas de stack trace dans la réponse'
    );
    
    // Test erreur serveur (ID invalide)
    const serverError = await makeRequest('/api/events/invalid-id');
    
    logTest(
      'Gère les erreurs serveur proprement',
      serverError.status >= 400,
      `Status: ${serverError.status}`
    );
    
    logTest(
      'Erreurs ne révèlent pas de détails internes',
      !serverError.data.stack,
      'Pas de stack trace exposée'
    );
    
  } catch (error) {
    logTest('Gestion des erreurs', false, error.message);
  }
}

// Fonction principale
async function runAllTests() {
  log('\n╔════════════════════════════════════════════════════════════╗', 'magenta');
  log('║     TESTS DE SÉCURITÉ - EventHub Backend API              ║', 'magenta');
  log('╚════════════════════════════════════════════════════════════╝', 'magenta');
  log(`\nTarget: ${BASE_URL}`, 'cyan');
  log(`Date: ${new Date().toLocaleString()}\n`, 'cyan');
  
  const startTime = Date.now();
  
  try {
    await testHealthCheck();
    await testSecurityHeaders();
    await testRateLimiting();
    await testInputValidation();
    await testAuthenticationFlow();
    await testSQLInjectionProtection();
    await testXSSProtection();
    await testCORS();
    await testErrorHandling();
    
  } catch (error) {
    log(`\n❌ Erreur fatale: ${error.message}`, 'red');
  }
  
  const endTime = Date.now();
  const duration = ((endTime - startTime) / 1000).toFixed(2);
  
  // Résumé
  logSection('RÉSUMÉ');
  log(`  Tests réussis: ${passedTests}`, passedTests > 0 ? 'green' : 'reset');
  log(`  Tests échoués: ${failedTests}`, failedTests > 0 ? 'red' : 'reset');
  log(`  Avertissements: ${warnings}`, warnings > 0 ? 'yellow' : 'reset');
  log(`  Durée: ${duration}s\n`);
  
  // Score de sécurité
  const totalTests = passedTests + failedTests;
  const score = totalTests > 0 ? Math.round((passedTests / totalTests) * 100) : 0;
  
  log('╔════════════════════════════════════════════════════════════╗', 'cyan');
  log(`║  SCORE DE SÉCURITÉ: ${score}%${' '.repeat(43 - score.toString().length)}║`, 
      score >= 90 ? 'green' : score >= 70 ? 'yellow' : 'red');
  log('╚════════════════════════════════════════════════════════════╝', 'cyan');
  
  if (score >= 90) {
    log('\n✅ Excellent! Votre API est bien sécurisée.', 'green');
  } else if (score >= 70) {
    log('\n⚠️  Bien, mais certaines améliorations sont recommandées.', 'yellow');
  } else {
    log('\n❌ Attention! Des problèmes de sécurité importants ont été détectés.', 'red');
  }
  
  // Recommandations
  if (warnings > 0 || failedTests > 0) {
    log('\n📋 RECOMMANDATIONS:', 'cyan');
    
    if (failedTests > 0) {
      log('  • Corriger les tests échoués en priorité', 'yellow');
    }
    
    if (warnings > 0) {
      log('  • Examiner les avertissements et ajuster la configuration', 'yellow');
    }
    
    log('  • Consulter le rapport DevSecOps pour plus de détails', 'yellow');
    log('  • Exécuter ce test régulièrement (CI/CD)', 'yellow');
    log('  • Activer le mode VERBOSE pour plus de détails: VERBOSE=true node test-security.js\n', 'yellow');
  }
  
  // Code de sortie
  process.exit(failedTests > 0 ? 1 : 0);
}

// Exécution
if (require.main === module) {
  runAllTests().catch(error => {
    log(`\n❌ Erreur fatale: ${error.message}`, 'red');
    console.error(error);
    process.exit(1);
  });
}

module.exports = { runAllTests, makeRequest };