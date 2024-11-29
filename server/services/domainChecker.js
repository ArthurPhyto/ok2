import whois from 'whois-json';
import dns from 'dns';
import { promisify } from 'util';

const resolveDns = promisify(dns.resolve);
const resolveNs = promisify(dns.resolveNs);
const resolveMx = promisify(dns.resolveMx);
const resolveA = promisify(dns.resolve4);

export async function lookupDomain(domain) {
  try {
    const checks = {
      ns: { status: 'pending', result: null },
      a: { status: 'pending', result: null },
      mx: { status: 'pending', result: null },
      whois: { status: 'pending', result: null }
    };

    // 1. Vérification des serveurs DNS (NS)
    try {
      const nsRecords = await resolveNs(domain);
      checks.ns = { status: 'success', result: nsRecords };
    } catch (error) {
      checks.ns = { status: 'error', error: error.message };
    }

    // 2. Vérification des enregistrements A
    try {
      const aRecords = await resolveA(domain);
      checks.a = { status: 'success', result: aRecords };
    } catch (error) {
      checks.a = { status: 'error', error: error.message };
    }

    // 3. Vérification des enregistrements MX
    try {
      const mxRecords = await resolveMx(domain);
      checks.mx = { status: 'success', result: mxRecords };
    } catch (error) {
      checks.mx = { status: 'error', error: error.message };
    }

    // 4. Vérification WHOIS
    try {
      const whoisResult = await whois(domain);
      if (whoisResult.expirationDate) {
        const expirationDate = new Date(whoisResult.expirationDate);
        const now = new Date();
        checks.whois = {
          status: 'success',
          result: {
            expirationDate,
            isExpired: expirationDate < now
          }
        };
      } else {
        checks.whois = {
          status: 'warning',
          error: 'Pas de date d\'expiration trouvée'
        };
      }
    } catch (error) {
      checks.whois = { status: 'error', error: error.message };
    }

    // Analyse des résultats
    const summary = [];
    let isExpired = false;

    // Vérification NS
    if (checks.ns.status === 'error') {
      summary.push('✗ Pas de serveurs DNS');
      isExpired = true;
    } else {
      summary.push('✓ Serveurs DNS présents');
    }

    // Vérification A
    if (checks.a.status === 'error') {
      summary.push('✗ Pas d\'enregistrement A');
      isExpired = true;
    } else {
      summary.push('✓ Enregistrements A présents');
    }

    // Vérification MX
    if (checks.mx.status === 'error') {
      summary.push('✗ Pas d\'enregistrement MX');
    } else {
      summary.push('✓ Enregistrements MX présents');
    }

    // Vérification WHOIS
    if (checks.whois.status === 'success') {
      if (checks.whois.result.isExpired) {
        summary.push(`✗ WHOIS: Domaine expiré depuis ${checks.whois.result.expirationDate.toLocaleDateString()}`);
        isExpired = true;
      } else {
        summary.push(`✓ WHOIS: Expire le ${checks.whois.result.expirationDate.toLocaleDateString()}`);
      }
    } else if (checks.whois.status === 'warning') {
      summary.push('⚠ WHOIS: Pas de date d\'expiration trouvée');
    } else {
      summary.push(`✗ WHOIS: ${checks.whois.error}`);
    }

    return {
      isExpired,
      reason: summary.join('\n'),
      checks
    };
  } catch (error) {
    console.error(`Erreur lors de la vérification du domaine ${domain}:`, error);
    throw error;
  }
}