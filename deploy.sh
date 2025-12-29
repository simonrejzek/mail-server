#!/bin/bash

echo "🚀 Cloudflare Email API - Quick Deploy to Render.com"
echo "=================================================="
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install git first:"
    echo "   sudo apt install git"
    exit 1
fi

echo "📝 Step 1: Configure Git (if not done)"
echo "--------------------------------------"
read -p "Enter your GitHub username: " github_user
read -p "Enter your GitHub email: " github_email

git config --global user.name "$github_user"
git config --global user.email "$github_email"

echo ""
echo "✅ Git configured!"
echo ""

echo "📝 Step 2: Initialize Git Repository"
echo "-------------------------------------"
cd "$(dirname "$0")"

if [ -d ".git" ]; then
    echo "⚠️  Git repository already exists. Skipping..."
else
    git init
    echo "✅ Git initialized!"
fi

echo ""
echo "📝 Step 3: Add and Commit Files"
echo "--------------------------------"
git add .
git commit -m "Initial commit - Cloudflare Email API Server"
echo "✅ Files committed!"

echo ""
echo "📝 Step 4: Create GitHub Repository"
echo "------------------------------------"
echo "Please do this manually:"
echo "1. Go to: https://github.com/new"
echo "2. Repository name: cloudflare-email-api"
echo "3. Make it PUBLIC (required for free Render)"
echo "4. Click 'Create repository'"
echo ""
read -p "Press Enter when you've created the GitHub repo..."

echo ""
read -p "Enter your GitHub repository URL (e.g., https://github.com/username/cloudflare-email-api.git): " repo_url

git remote add origin "$repo_url" 2>/dev/null || git remote set-url origin "$repo_url"
git branch -M main
git push -u origin main

echo ""
echo "✅ Code pushed to GitHub!"
echo ""

echo "📝 Step 5: Deploy on Render"
echo "---------------------------"
echo "Now follow these steps:"
echo ""
echo "1. Go to: https://render.com"
echo "2. Sign up with GitHub"
echo "3. Click 'New +' → 'Web Service'"
echo "4. Connect your 'cloudflare-email-api' repository"
echo "5. Configure:"
echo "   - Runtime: Python 3"
echo "   - Build: pip install -r requirements.txt"
echo "   - Start: gunicorn app:app"
echo "   - Plan: FREE"
echo ""
echo "6. Add Environment Variables:"
echo "   CLOUDFLARE_API_TOKEN=gGPiTHCgoyliIiVmicp0u9ImJpdeLiizU2Jcs0-W"
echo "   CLOUDFLARE_ZONE_ID=ea0203c466fb571150bffff1d54cc128"
echo "   DOMAIN_NAME=axilon.app"
echo "   DESTINATION_EMAIL=axilon.contact@gmail.com"
echo "   API_PASSWORD=terimkcchut976"
echo "   FLASK_DEBUG=false"
echo ""
echo "7. Click 'Create Web Service'"
echo ""
echo "🎉 Done! Your email API will be live in 2-5 minutes!"
echo ""
echo "📖 For detailed instructions, see: FREE_DEPLOYMENT.md"
