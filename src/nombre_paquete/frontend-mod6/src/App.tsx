import React, { useState } from 'react';
import './App.css';
import Header from './Header';

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

const IPInputBox: React.FC<{ onCheck: () => void }> = ({ onCheck }) => (
  <div>
    <div>
      <input placeholder="Enter IP" />
      <button onClick={onCheck}>Check IP</button>
    </div>
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
      <ResultCard title="Openai" content={data.openai} />
      <ResultCard title="DeepSeek" content={data.deepseek} />
    </div>
  );
};

const MoreInfoGrid: React.FC<{ data: MoreData }> = ({ data }) => (
  <div className="grid">
    <ResultCard title="VirusTotal" content={data.VirusTotal} />
    <ResultCard title="Whois" content={data.whois} />
    <ResultCard title="AbuseIPDB" content={data.AbuseIPDB} />
  </div>
);

const App: React.FC = () => {
  const [result, setResult] = useState<IPData | null>(null);
  const [loading, setLoading] = useState(false);
  const [moreData, setMoreData] = useState<MoreData | null>(null);
  const [showMore, setShowMore] = useState(false);

  const fetchData = () => {
    const mocked: IPData = {
      claude: {"response":{"Summary":"The IP address 115.58.133.36 is located in China (Zhengzhou, Henan province) and is part of the China Unicom network (AS4837). It has several risk indicators: 11 security vendors on VirusTotal have flagged it as malicious, it has an openai confidence score of 5 with 2 abuse reports from 1 distinct user, and the most recent report was on July 20, 2025. VirusTotal scanning reveals an FTP service running on port 21 with failed login attempts. The IP belongs to a fixed-line ISP and is associated with the hostname 'hn.kd.ny.adsl'. Chinese IP addresses, particularly those with detected malicious activity, are frequently used in scanning and exploitation attempts against global targets.","Recommendation":"This IP address should be monitored and potentially blocked if not required for legitimate business operations. Implement firewall rules to restrict access from this IP, especially to FTP services and other sensitive ports. If you observe traffic from this IP in your logs, investigate for potential unauthorized access attempts. Consider adding this IP to your threat intelligence feeds for continued monitoring. Since it's a China-based IP with known malicious indicators, apply the principle of least privilege if you must interact with this network range.","Score":62}},

      openai: {"response":{"Summary":"The IP address 115.58.133.36 is associated with China Unicom Henan province network, located in Zhengzhou, China. The IP has a low reputation score and recent malicious activity reports, although mostly benign with some suspicious and undetected flags. It operates on port 21, indicating potential for FTP-related services, which could be exploited if not properly secured.","Recommendation":"Implement strict security measures such as disabling anonymous FTP access, applying firewalls, monitoring for unusual activity, and conducting regular security audits. Consider blocking or restricting access to this IP if unnecessary, and keep systems updated to mitigate potential threats.","Score":40}},

      
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
      const data: MoreData = {
        VirusTotal: {
          response: {
            data: {
              links: {
                self: "https://www.virustotal.com/api/v3/ip_addresses/115.58.133.36"
              },
              attributes: {
                last_analysis_date: 1753051454,
                last_analysis_stats: {
                  malicious: 7,
                  suspicious: 0,
                  undetected: 32,
                  harmless: 55,
                  timeout: 0
                },
                total_votes: {
                  harmless: 0,
                  malicious: 0
                }
              }
            }
          }
        },
        whois: {
          response: {
            message: "Unknown"
          }
        },
        AbuseIPDB: {
          response: {
            isWhitelisted: false,
            abuseConfidenceScore: 5,
            countryCode: "CN",
            usageType: "Fixed Line ISP",
            domain: "chinaunicom.cn",
            isTor: false,
            totalReports: 2,
            lastReportedAt: "2025-07-20T12:35:30+00:00"
          }
        }
      };
  
      // Extract and beautify the data before setting state
      const beautifiedData: MoreData = {
        VirusTotal: {
          Malicious: data.VirusTotal.response.data.attributes.last_analysis_stats.malicious,
          Suspicious: data.VirusTotal.response.data.attributes.last_analysis_stats.suspicious,
          Undetected: data.VirusTotal.response.data.attributes.last_analysis_stats.undetected,
          Harmless: data.VirusTotal.response.data.attributes.last_analysis_stats.harmless,
          Timeout: data.VirusTotal.response.data.attributes.last_analysis_stats.timeout,
          Link: data.VirusTotal.response.data.links.self
        },
        whois: {
          Message: data.whois.response.message
        },
        AbuseIPDB: {
          Whitelisted: data.AbuseIPDB.response.isWhitelisted ? "Yes" : "No",
          ConfidenceScore: data.AbuseIPDB.response.abuseConfidenceScore,
          Country: data.AbuseIPDB.response.countryCode,
          UsageType: data.AbuseIPDB.response.usageType,
          Domain: data.AbuseIPDB.response.domain,
          Tor: data.AbuseIPDB.response.isTor ? "Yes" : "No",
          TotalReports: data.AbuseIPDB.response.totalReports,
          LastReported: data.AbuseIPDB.response.lastReportedAt
        }
      };
  
      setMoreData(beautifiedData);
      setShowMore(true);
    } catch (err) {
      console.error('Error fetching IPify data:', err);
    } finally {
      setLoading(false);
    }
  };;

  return (
    <div>
      <Header />
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