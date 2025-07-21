import React, { useState } from 'react';
import './App.css';

type IPData = {
  virusTotal: any;
  abuseIPDB: any;
  whois: any;
};

type MoreData = {
  shodan: any;
  greynoise: any;
  ipinfo: any;
};

const IPInputBox: React.FC<{ onCheck: () => void }> = ({ onCheck }) => (
  <div>
    <input placeholder="Enter IP" />
    <button onClick={onCheck}>Check IP</button>
  </div>
);

const ResultCard: React.FC<{ title: string; content: any }> = ({ title, content }) => {
  const parsed =
    typeof content === 'string'
      ? [['Text', content]]
      : Object.entries(content);

  return (
    <div className="result-card">
      <h3>{title}</h3>
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
      <ResultCard title="VirusTotal" content={data.virusTotal} />
      <ResultCard title="AbuseIPDB" content={data.abuseIPDB} />
      <ResultCard title="Whois" content={data.whois} />
    </div>
  );
};

const MoreInfoGrid: React.FC<{ data: MoreData }> = ({ data }) => (
  <div className="grid">
    <ResultCard title="Shodan (IPify)" content={data.shodan} />
    <ResultCard title="GreyNoise (IPify)" content={data.greynoise} />
    <ResultCard title="IPInfo (IPify)" content={data.ipinfo} />
  </div>
);

const App: React.FC = () => {
  const [result, setResult] = useState<IPData | null>(null);
  const [loading, setLoading] = useState(false);
  const [moreData, setMoreData] = useState<MoreData | null>(null);
  const [showMore, setShowMore] = useState(false);

  const fetchData = () => {
    const mocked: IPData = {
      virusTotal: { Malicious: 11, Suspicious: 3 },
      abuseIPDB: { Reports: 177, Confidence: 100 },
      whois: { CIDR: '185.220.101.0/27', Org: 'Artikel10 e.V.' },
    };
    setResult(mocked);
  };

  const fetchMoreData = async () => {
    setLoading(true);
    try {
      const [res1, res2, res3] = await Promise.all([
        fetch("http://localhost:8000/api/v1/deepseek?source=shodan").then(r => r.json()),
        fetch("http://localhost:8000/api/v1/deepseek?source=greynoise").then(r => r.json()),
        fetch("http://localhost:8000/api/v1/deepseek?source=ipinfo").then(r => r.json()),
      ]);

      const data: MoreData = {
        shodan: res1,
        greynoise: res2,
        ipinfo: res3,
      };

      setMoreData(data);
      setShowMore(true);
    } catch (err) {
      console.error('Error fetching IPify data:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2>RiskScope - IP Threat Intelligence Checker</h2>
      <IPInputBox onCheck={fetchData} />
      <IPResultsGrid data={result} />

      {result && (
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <button onClick={fetchMoreData} disabled={loading}>
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