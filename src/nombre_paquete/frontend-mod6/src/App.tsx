import React, { useState } from 'react';
import './App.css';
import Header from './Header';
import OpenAILogo from './assets/OpenaiLogo.png';
import ClaudeLogo from './assets/ClaudeLogo.png';
import DeepSeekLogo from './assets/DeepSeekLogo.png';
import VirusTotalLogo from './assets/VirusTotalLogo.png';
import WhoisLogo from './assets/WhoISLogo.png';
import AbuseIPDBLogo from './assets/AbuseIPDBLogo.png';

type IPData = {
  claude: any;
  openai: any;
  deepseek: any;
};

type MoreData = {
  VirusTotal: any;
  whois: any;
  AbuseIPDB: any;
};

const App: React.FC = () => {
  const [result, setResult] = useState<IPData | null>(null);
  const [loading, setLoading] = useState(false);
  const [moreData, setMoreData] = useState<MoreData | null>(null);
  const [showMore, setShowMore] = useState(false);
  const [ip, setIp] = useState<string>("");

  const fetchData = async () => {
    if (!ip) return;
    try {
      // Fetch Claude
      const claudeRes = await fetch('http://localhost:8000/api/v1/claude', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc: ip }),
      });
      const claudeResult = await claudeRes.json();

      // Fetch OpenAI
      const openaiRes = await fetch('http://localhost:8000/api/v1/openai', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc: ip }),
      });
      const openaiResult = await openaiRes.json();

      // Fetch DeepSeek
      const deepseekRes = await fetch('http://localhost:8000/api/v1/deepseek', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc: ip }),
      });
      const deepseekResult = await deepseekRes.json();

      const extractedData = {
        claude: claudeResult.response,
        openai: openaiResult.response,
        deepseek: deepseekResult.response,
      };

      setResult(extractedData);
      setShowMore(false);
      setMoreData(null);
    } catch (err) {
      console.error('Error fetching main IP data:', err);
    }
  };

  const fetchMoreData = async () => {
    if (!ip) return;
    setLoading(true);
    try {
      // Fetch VirusTotal data
      const vtRes = await fetch('http://localhost:8000/api/v1/virustotal', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc: ip }),
      });
      const vtResult = await vtRes.json();
      const vt = vtResult.response.data;

      // Fetch Whois data
      const whoisRes = await fetch('http://localhost:8000/api/v1/whois', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc: ip }),
      });
      const whoisResult = await whoisRes.json();
      const whois = whoisResult.response.data;

      // Fetch AbuseIPDB data
      const abuseRes = await fetch('http://localhost:8000/api/v1/abuseipdb', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ioc: ip }),
      });
      const abuseResult = await abuseRes.json();
      const abuse = abuseResult.response;

      // Beautify and set state
      const beautifiedData: MoreData = {
        VirusTotal: {
          Malicious: vt.attributes.last_analysis_stats.malicious,
          Suspicious: vt.attributes.last_analysis_stats.suspicious,
          Undetected: vt.attributes.last_analysis_stats.undetected,
          Harmless: vt.attributes.last_analysis_stats.harmless,
          Timeout: vt.attributes.last_analysis_stats.timeout,
          Link: vt.links.self
        },
        whois: whois,
        AbuseIPDB: {
          Whitelisted: abuse.isWhitelisted ? "Yes" : "No",
          ConfidenceScore: abuse.abuseConfidenceScore,
          Country: abuse.countryCode,
          UsageType: abuse.usageType,
          Domain: abuse.domain,
          Tor: abuse.isTor ? "Yes" : "No",
          TotalReports: abuse.totalReports,
          LastReported: abuse.lastReportedAt
        }
      };

      setMoreData(beautifiedData);
      setShowMore(true);
    } catch (err) {
      console.error('Error fetching more data:', err);
    } finally {
      setLoading(false);
    }
  };

  const IPInputBox: React.FC<{ onCheck: () => void }> = ({ onCheck }) => (
    <div>
      <p id='ip-input-box-label-text'>Welcome! Please enter a valid IP address to begin</p>
      <div id='ip-input-box'>
        <input
          placeholder="IP Address"
          value={ip}
          onChange={e => setIp(e.target.value)}
        />
        <button onClick={onCheck} disabled={!ip}>Check IP</button>
      </div>
    </div>
  );

  const ResultCard: React.FC<{ title: string; content: any; logo?: string }> = ({ title, content, logo }) => {
    
    // If content is empty, null, or undefined, show default message
    const isEmpty =
      content === undefined ||
      content === null ||
      (typeof content === 'object' && Object.keys(content).length === 0) ||
      (typeof content === 'string' && content.trim() === '');

    const parsed = isEmpty
      ? [['Text', 'This resource was not used in the data adquisition pipeline used by the models']]
      : typeof content === 'string'
        ? [['Text', content]]
        : Object.entries(content);

    return (
      <div className="result-card">
        <div className="card-header">
          {logo && <img src={logo} alt={`${title} logo`} className="card-logo" />}
          <h3>{title}</h3>
        </div>
        <div className="card-content">
          {parsed.map(([key, value], idx) => (
            <div key={idx} className="card-row">
              <span className="card-key">{key}</span>
              <span className="card-value">
                {Array.isArray(value) ? value.join(', ') : value?.toString()}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const IPResultsGrid: React.FC<{ data: IPData | null }> = ({ data }) => {
    if (!data) return null;
    return (
      <div className="grid">
        <ResultCard title="Claude" content={data.claude} logo={ClaudeLogo} />
        <ResultCard title="Openai" content={data.openai} logo={OpenAILogo} />
        <ResultCard title="DeepSeek" content={data.deepseek} logo={DeepSeekLogo} />
      </div>
    );
  };

  const MoreInfoGrid: React.FC<{ data: MoreData }> = ({ data }) => (
    <div className="grid">
      <ResultCard title="VirusTotal" content={data.VirusTotal} logo={VirusTotalLogo} />
      <ResultCard title="Whois" content={data.whois} logo={WhoisLogo} />
      <ResultCard title="AbuseIPDB" content={data.AbuseIPDB} logo={AbuseIPDBLogo} />
    </div>
  );

  return (
    <div>
      <Header />
      <IPInputBox onCheck={fetchData} />
      <IPResultsGrid data={result} />

      {result && (
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <button onClick={fetchMoreData} disabled={loading || !ip}>
            {loading ? 'Loading...' : 'Show More Info'}
          </button>
        </div>
      )}

      {showMore && moreData && (
        <div style={{ marginTop: '2rem' }}>
          <h3 style={{ textAlign: 'center' }}>Additional Intelligence</h3>
          <MoreInfoGrid data={moreData} />
        </div>
      )}
    </div>
  );
};

export default App;