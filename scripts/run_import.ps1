# Nexus Automation Framework - CVE Database Import Script (Windows PowerShell)
# This script automates the CVE database import process

Write-Host "🔥 Nexus Automation Framework - CVE Database Import" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green

# Check if we're in the right directory
if (-not (Test-Path "..\nexus_framework\__init__.py")) {
    Write-Host "❌ Error: Please run this script from the scripts\ directory" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Check if knowledge database exists
if (Test-Path "..\knowledge.db") {
    Write-Host "📊 Existing database found. Current stats:" -ForegroundColor Cyan
    python -c "
import sys
sys.path.append('..')
from nexus_framework.strategic.knowledge import KnowledgeDatabase
db = KnowledgeDatabase()
stats = db.get_import_statistics()
print(f'   Total CVEs: {stats.get(\"total_cves\", 0)}')
print(f'   Critical: {stats.get(\"severity_distribution\", {}).get(\"CRITICAL\", 0)}')
print(f'   High: {stats.get(\"severity_distribution\", {}).get(\"HIGH\", 0)}')
"
    
    $continue = Read-Host "⚠️ Database exists. Continue import? (y/N): "
    if ($continue -notmatch '^[Yy]$') {
        Write-Host "❌ Import cancelled" -ForegroundColor Red
        exit 0
    }
}

# Ask user for import type
Write-Host ""
Write-Host "🎯 Select import type:" -ForegroundColor Yellow
Write-Host "1) Critical CVEs only (Recommended - ~5-15 min)" -ForegroundColor White
Write-Host "2) NVD API only (Official source - ~30 min)" -ForegroundColor White
Write-Host "3) GitHub releases only (Community source - ~45 min)" -ForegroundColor White
Write-Host "4) All sources (Complete database - ~2-4 hours)" -ForegroundColor White
Write-Host "5) Custom import with limits" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter choice (1-5): "

switch ($choice) {
    "1" {
        Write-Host "🔥 Starting critical CVEs import..." -ForegroundColor Green
        python import_cve_database.py --source critical
    }
    "2" {
        Write-Host "🏛️ Starting NVD API import..." -ForegroundColor Green
        python import_cve_database.py --source nvd --limit 5000
    }
    "3" {
        Write-Host "📥 Starting GitHub releases import..." -ForegroundColor Green
        python import_cve_database.py --source github --limit 10000
    }
    "4" {
        Write-Host "🌍 Starting comprehensive import from all sources..." -ForegroundColor Yellow
        $continue = Read-Host "⚠️ This may take 2-4 hours. Continue? (y/N): "
        if ($continue -match '^[Yy]$') {
            python import_cve_database.py --source all --limit 25000
        } else {
            Write-Host "❌ Import cancelled" -ForegroundColor Red
            exit 0
        }
    }
    "5" {
        Write-Host "🔧 Custom import configuration" -ForegroundColor Yellow
        $source = Read-Host "Source (nvd, github, critical, all): "
        $limit = Read-Host "Limit (number of CVEs, leave empty for unlimited): "
        
        if ($limit) {
            python import_cve_database.py --source $source --limit $limit
        } else {
            python import_cve_database.py --source $source
        }
    }
    default {
        Write-Host "❌ Invalid choice" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "📊 Import completed! Final statistics:" -ForegroundColor Green
python -c "
import sys
sys.path.append('..')
from nexus_framework.strategic.knowledge import KnowledgeDatabase
db = KnowledgeDatabase()
stats = db.get_import_statistics()
print(f'   Total CVEs: {stats.get(\"total_cves\", 0)}')
print(f'   Critical: {stats.get(\"severity_distribution\", {}).get(\"CRITICAL\", 0)}')
print(f'   High: {stats.get(\"severity_distribution\", {}).get(\"HIGH\", 0)}')
print(f'   Medium: {stats.get(\"severity_distribution\", {}).get(\"MEDIUM\", 0)}')
print(f'   Low: {stats.get(\"severity_distribution\", {}).get(\"LOW\", 0)}')
print(f'   With exploits: {stats.get(\"exploit_availability\", {}).get(True, 0)}')
print(f'   Recent (30 days): {stats.get(\"recent_cves_30_days\", 0)}')
"

Write-Host ""
Write-Host "✅ CVE database import completed successfully!" -ForegroundColor Green
Write-Host "🚀 The Nexus Automation Framework now has access to a comprehensive vulnerability database." -ForegroundColor Green
