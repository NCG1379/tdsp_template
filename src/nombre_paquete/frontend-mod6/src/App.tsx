import React, { useState } from 'react';
import './App.css';

type IPData = {
  claude: any;
  openai: any;
  deepseek: any;
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
      <ResultCard title="Claude" content={data.claude} />
      <ResultCard title="openai" content={data.openai} />
      <ResultCard title="deepseek" content={data.deepseek} />
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
      claude: {"response":{"Summary":"The IP address 115.58.133.36 is located in China (Zhengzhou, Henan province) and is part of the China Unicom network (AS4837). It has several risk indicators: 11 security vendors on VirusTotal have flagged it as malicious, it has an openai confidence score of 5 with 2 abuse reports from 1 distinct user, and the most recent report was on July 20, 2025. Shodan scanning reveals an FTP service running on port 21 with failed login attempts. The IP belongs to a fixed-line ISP and is associated with the hostname 'hn.kd.ny.adsl'. Chinese IP addresses, particularly those with detected malicious activity, are frequently used in scanning and exploitation attempts against global targets.","Recommendation":"This IP address should be monitored and potentially blocked if not required for legitimate business operations. Implement firewall rules to restrict access from this IP, especially to FTP services and other sensitive ports. If you observe traffic from this IP in your logs, investigate for potential unauthorized access attempts. Consider adding this IP to your threat intelligence feeds for continued monitoring. Since it's a China-based IP with known malicious indicators, apply the principle of least privilege if you must interact with this network range.","Score":62}},

      openai: {"response": {"Summary": "The IP address 115.58.133.36 is associated with China Unicom in Henan, China. It is part of a regional backbone network and has a low reputation score with no significant malicious activity reported. However, it is listed with some reports of suspicious activity and has an abuse confidence score of 5. The IP runs on a fixed line ISP network and has been reported a few times, with recent activity indicating potential vulnerabilities, especially given the open FTP port at 21 which shows failed login attempts.","Recommendation": "Monitor network activity associated with this IP closely. Ensure all services, especially FTP, are properly secured with strong authentication and encryption options. Conduct regular vulnerability assessments and consider blocking or restricting access if no legitimate use is identified. Keep software and hardware updated to prevent exploitation.","Score": 42}},

      
      deepseek: {"response": {"Summary": "The IP address 115.58.133.36 is associated with China Unicom in Henan, China. It is part of a regional backbone network and has a low reputation score with no significant malicious activity reported. However, it is listed with some reports of suspicious activity and has an abuse confidence score of 5. The IP runs on a fixed line ISP network and has been reported a few times, with recent activity indicating potential vulnerabilities, especially given the open FTP port at 21 which shows failed login attempts.","Recommendation": "Monitor network activity associated with this IP closely. Ensure all services, especially FTP, are properly secured with strong authentication and encryption options. Conduct regular vulnerability assessments and consider blocking or restricting access if no legitimate use is identified. Keep software and hardware updated to prevent exploitation.","Score": 42}},
    };

    // Extract the 'response' field to get to the actual data
    const extractedData = {
      deepseek: mocked.deepseek.response,
      claude: mocked.claude.response,
      openai: mocked.openai.response,
    }

    setResult(extractedData);
  };

  const fetchMoreData = async () => {
    setLoading(true);
    try {
      const [res1, res2, res3] = await Promise.all([
        fetch('https://api.ipify.org?format=json').then(r => r.json()),
        fetch('https://api.ipify.org?format=json').then(r => r.json()),
        fetch('https://api.ipify.org?format=json').then(r => r.json()),
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