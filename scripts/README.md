# CVE Database Import Scripts

## 🎯 Overview

This directory contains scripts to populate the Nexus Automation Framework with the most complete CVE database possible from multiple authoritative sources.

## 📊 Data Sources

### 1. **NVD JSON 2.0 API** (Official US Government)
- **Source**: https://nvd.nist.gov/vuln/data-feeds
- **Coverage**: 200,000+ CVEs
- **Update Frequency**: Every 2 hours
- **Format**: JSON 2.0
- **Reliability**: ⭐⭐⭐⭐⭐ (Official)

### 2. **CVEProject/cvelistV5** (Official CVE Records)
- **Source**: https://github.com/CVEProject/cvelistV5
- **Coverage**: All CVE records
- **Update Frequency**: Real-time
- **Format**: JSON
- **Reliability**: ⭐⭐⭐⭐⭐ (Official)

### 3. **fkie-cad/nvd-json-data-feeds** (Community Mirror)
- **Source**: https://github.com/fkie-cad/nvd-json-data-feeds
- **Coverage**: Historical + Recent CVEs
- **Update Frequency**: Daily
- **Format**: JSON (reconstructed NVD feeds)
- **Reliability**: ⭐⭐⭐⭐ (Community)

### 4. **olbat/nvdcve** (Daily Updates)
- **Source**: https://github.com/olbat/nvdcve
- **Coverage**: NVD + CVE dictionary
- **Update Frequency**: Daily
- **Format**: JSON
- **Reliability**: ⭐⭐⭐⭐ (Community)

## 🚀 Usage

### Quick Start - Critical CVEs Only
```bash
# Install dependencies
pip install -r scripts/requirements.txt

# Import only critical/high severity CVEs (recommended first)
python scripts/import_cve_database.py --source critical

# Import from NVD API only
python scripts/import_cve_database.py --source nvd --limit 1000

# Import from GitHub releases
python scripts/import_cve_database.py --source github --limit 2000
```

### Comprehensive Import
```bash
# Import from all sources (may take several hours)
python scripts/import_cve_database.py --source all

# Import with specific limit
python scripts/import_cve_database.py --source all --limit 5000
```

## 📈 Expected Results

### Critical CVEs Import (Recommended First)
- **Time**: 5-15 minutes
- **CVEs**: 1,000-3,000
- **Coverage**: Critical/High severity only
- **Storage**: ~5-15MB

### Full Import (All Sources)
- **Time**: 2-4 hours
- **CVEs**: 50,000-100,000+
- **Coverage**: Complete vulnerability database
- **Storage**: ~500MB-1GB

## 🔧 Configuration

### Database Location
```bash
# Default location (project root)
python scripts/import_cve_database.py --db-path knowledge.db

# Custom location
python scripts/import_cve_database.py --db-path /path/to/custom.db
```

### Rate Limiting
- **NVD API**: 5 requests per 30 seconds (automatically handled)
- **GitHub**: 60 requests per hour (automatically handled)
- **Script includes automatic delays** to respect limits

## 📊 Import Statistics

After import, check the database contents:
```python
from nexus_framework.strategic.knowledge import KnowledgeDatabase

db = KnowledgeDatabase()
stats = db.get_import_statistics()
print(f"Total CVEs: {stats['total_cves']}")
print(f"Critical: {stats['severity_distribution']['CRITICAL']}")
print(f"High: {stats['severity_distribution']['HIGH']}")
print(f"With exploits: {stats['exploit_availability'][True]}")
```

## 🔄 Maintenance

### Daily Updates
```bash
# Add new CVEs from last 24 hours
python scripts/import_cve_database.py --source nvd --limit 100

# Update from GitHub releases
python scripts/import_cve_database.py --source github --limit 500
```

### Weekly Full Sync
```bash
# Complete refresh from all sources
python scripts/import_cve_database.py --source all --limit 10000
```

## 🛡️ Security Considerations

### Data Sources Trust Level
1. **NVD API** - Official US Government source ✅
2. **CVEProject** - Official CVE Program ✅  
3. **Community repos** - Verified mirrors ⚠️
4. **Unknown sources** - Avoid ❌

### Validation
- All CVE IDs are validated against official format
- CVSS scores are verified for consistency
- Duplicate entries are automatically handled
- Malformed data is logged and skipped

## 🚨 Troubleshooting

### Common Issues

#### "Rate limit exceeded"
- **Solution**: Wait for automatic delay or reduce `--limit`
- **NVD**: 5 requests/30sec, script waits automatically

#### "Connection timeout"
- **Solution**: Check internet connection
- **Large files**: May need increased timeout

#### "Database locked"
- **Solution**: Ensure no other process is using the database
- **Restart**: Stop framework, run import, restart framework

#### "Memory error"
- **Solution**: Reduce `--limit` parameter
- **Large imports**: Use smaller batches

### Debug Mode
```bash
# Enable debug logging
python scripts/import_cve_database.py --source critical --debug
```

## 📈 Performance Optimization

### For Large Imports (>50,000 CVEs)
1. **Use SSD storage** for faster I/O
2. **Increase RAM** if memory errors occur
3. **Use smaller batches** (--limit 1000)
4. **Run during off-peak hours**

### Database Optimization
```sql
-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity);
CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cve_exploit ON cve_entries(exploit_available);
```

## 🎯 Best Practices

1. **Start Small**: Begin with `--source critical` to test
2. **Monitor Progress**: Check logs for import speed
3. **Validate Data**: Verify imported CVEs with search
4. **Regular Updates**: Schedule daily/weekly imports
5. **Backup Database**: Before major imports

## 📞 Support

For issues with the import scripts:
1. Check the logs for specific error messages
2. Verify internet connectivity
3. Ensure dependencies are installed
4. Check rate limiting status

## 🔄 Integration with Framework

The imported CVEs are automatically available to:
- **Strategic Brain Engine** for decision making
- **Vulnerability scanning** tools
- **Risk assessment** algorithms
- **Automated reporting** systems
