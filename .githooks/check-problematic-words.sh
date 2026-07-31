#!/bin/bash
# Git hook to check for problematic words in commits

# Define problematic words/patterns
PROBLEMATIC_PATTERNS=(
    # AI/Assistant references
    "claude|Claude"
    "anthropic|Anthropic"
    "AI-generated|ai-generated"
    "AI generated|ai generated"
    "artificial intelligence"
    "machine learning model"
    "language model"
    "Co-Authored-By:.*Claude"
    "noreply@anthropic"
    "Generated with.*Claude"
    "assistant|Assistant"
    "chatbot|Chatbot"
    
    # Generic/problematic code patterns (optional)
    "TODO:.*fix.*later"
    "HACK:"
    "XXX:"
    "FIXME:.*urgent"
    
    # Security issues
    "password.*=.*['\"]"
    "api_key.*=.*['\"]"
    "secret.*=.*['\"]"
    "token.*=.*['\"]"
    
    # Profanity/inappropriate content
    "wtf|WTF"
    "damn|DAMN"
    
    # Company/personal info that shouldn't be committed
    "internal only"
    "confidential"
    "do not distribute"
)

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to check content for problematic patterns
check_content() {
    local content="$1"
    local context="$2"
    local found_issues=0
    
    for pattern in "${PROBLEMATIC_PATTERNS[@]}"; do
        if echo "$content" | grep -iE "$pattern" > /dev/null 2>&1; then
            if [ $found_issues -eq 0 ]; then
                echo -e "${RED}❌ Problematic content found in $context:${NC}"
                found_issues=1
            fi
            echo -e "${YELLOW}  Pattern: $pattern${NC}"
            echo "$content" | grep -iE "$pattern" --color=always | head -3
            echo ""
        fi
    done
    
    return $found_issues
}

# Check commit message
if [ "$1" = "message" ]; then
    COMMIT_MSG_FILE="$2"
    if [ -f "$COMMIT_MSG_FILE" ]; then
        COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")
        check_content "$COMMIT_MSG" "commit message"
        exit $?
    fi
fi

# Check staged files
if [ "$1" = "files" ]; then
    echo "Checking staged files for problematic content..."
    
    # Get list of staged files
    STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
    
    FOUND_ISSUES=0
    for file in $STAGED_FILES; do
        # Skip binary files
        if file "$file" | grep -q "binary"; then
            continue
        fi
        
        # Skip the .githooks directory itself (it contains the patterns we're checking for!)
        case "$file" in
            .githooks/*)
                continue
                ;;
        esac
        
        # Skip certain file types
        case "$file" in
            *.jpg|*.png|*.gif|*.pdf|*.zip|*.tar|*.gz|*.pyc|*.so|*.dll)
                continue
                ;;
        esac

        # Skip the license reference data. It legitimately contains SPDX
        # identifiers and upstream URLs that trip the profanity and
        # hardcoded-secret patterns -- e.g. the WTFPL license id, and kernel
        # source URLs ending in "..._token.c".
        case "$file" in
            src/ossbomer/oslc/license_rules.json)
                continue
                ;;
        esac

        # Skip vendored third-party source documents. These are published
        # standards reproduced verbatim as audit evidence, so their wording is
        # not ours to edit -- the OpenChain Telco Guide has a section titled
        # "SBOM Confidentiality", which trips the confidential-markers pattern.
        case "$file" in
            docs/sources/documents/*)
                continue
                ;;
        esac
        
        # Check file content
        if [ -f "$file" ]; then
            CONTENT=$(git diff --cached "$file" | grep "^+[^+]" | sed 's/^+//')
            if [ -n "$CONTENT" ]; then
                check_content "$CONTENT" "file: $file"
                if [ $? -ne 0 ]; then
                    FOUND_ISSUES=1
                fi
            fi
        fi
    done
    
    exit $FOUND_ISSUES
fi

# Usage instructions if called without arguments
echo "Usage:"
echo "  $0 message <commit-msg-file>  - Check commit message"
echo "  $0 files                       - Check staged files"
echo ""
echo "Checks for problematic words including:"
echo "  - AI/Claude references"
echo "  - Security issues (hardcoded passwords/keys)"
echo "  - TODO/FIXME/HACK markers"
echo "  - Inappropriate language"
echo "  - Confidential markers"