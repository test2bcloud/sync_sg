#!/bin/bash

set -o pipefail

# Constants

MY_HOME_IP="$1/32" 
YAML_FILE="security-group.yaml"
GIT_REPO_URL="git@github.com:test2bcloud/sync_sg.git"
GIT_BRANCH="main"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
    echo -e "[DEBUG] $1" >&2
}

# Error handler
error_exit() {
    log_error "$1"
    exit 1
}

# Get EC2 metadata token
get_metadata_token() {
    log_info "Getting EC2 metadata token..."
    
    local token
    if ! token=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
        -s -f --connect-timeout 5 2>&1); then
        error_exit "Failed to get metadata token. Are you running on EC2? Error: $token"
    fi
    
    if [ -z "$token" ]; then
        error_exit "Metadata token is empty"
    fi
    
    log_debug "Token retrieved successfully (length: ${#token})"
    echo "$token"
}

# Get region from EC2 metadata
get_region() {
    local token=$1
    log_info "Fetching region from EC2 metadata..."
    
    local region
    if ! region=$(curl -H "X-aws-ec2-metadata-token: $token" \
        -s -f --connect-timeout 5 http://169.254.169.254/latest/meta-data/placement/region 2>&1); then
        error_exit "Failed to get region. Error: $region"
    fi
    
    if [ -z "$region" ]; then
        error_exit "Region is empty"
    fi
    
    log_debug "Region: $region"
    echo "$region"
}

# Get instance ID from EC2 metadata
get_instance_id() {
    local token=$1
    log_info "Fetching instance ID from EC2 metadata..."
    
    local instance_id
    if ! instance_id=$(curl -H "X-aws-ec2-metadata-token: $token" \
        -s -f --connect-timeout 5 http://169.254.169.254/latest/meta-data/instance-id 2>&1); then
        error_exit "Failed to get instance ID. Error: $instance_id"
    fi
    
    if [ -z "$instance_id" ]; then
        error_exit "Instance ID is empty"
    fi
    
    log_debug "Instance ID: $instance_id"
    echo "$instance_id"
}

# Parse YAML and extract expected rules
parse_yaml_rules() {
    log_info "Parsing YAML file to extract expected rules..."
    
    if [ ! -f "$YAML_FILE" ]; then
        error_exit "YAML file not found: $YAML_FILE"
    fi
    
    local ssh_rules=""
    local http_rules=""
    local in_ssh_section=0
    local in_http_section=0
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*ssh:[[:space:]]*$ ]]; then
            in_ssh_section=1
            in_http_section=0
            continue
        fi
        
        if [[ "$line" =~ ^[[:space:]]*http:[[:space:]]*$ ]]; then
            in_http_section=1
            in_ssh_section=0
            continue
        fi
        
        if [[ "$line" =~ ^[[:space:]]*[a-z]+:[[:space:]]*$ ]]; then
            in_ssh_section=0
            in_http_section=0
        fi
        
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+([0-9./]+)[[:space:]]*$ ]]; then
            local cidr="${BASH_REMATCH[1]}"
            if [ $in_ssh_section -eq 1 ]; then
                ssh_rules="$ssh_rules $cidr"
            elif [ $in_http_section -eq 1 ]; then
                http_rules="$http_rules $cidr"
            fi
        fi
    done < "$YAML_FILE"
    
    ssh_rules=$(echo "$ssh_rules" | xargs)
    http_rules=$(echo "$http_rules" | xargs)
    
    log_debug "Expected SSH (port 22) rules from YAML: $ssh_rules"
    log_debug "Expected HTTP (port 80) rules from YAML: $http_rules"
    
    # Return both as associative array style string
    echo "SSH:$ssh_rules|HTTP:$http_rules"
}

# Find security group by matching YAML rules with actual security groups
find_security_group() {
    local region=$1
    local yaml_rules=$2
    
    local ssh_part=$(echo "$yaml_rules" | cut -d'|' -f1 | cut -d':' -f2)
    local http_part=$(echo "$yaml_rules" | cut -d'|' -f2 | cut -d':' -f2)
    
    log_info "Finding security group that matches YAML template..."
    log_info "Expected SSH (port 22) CIDRs: $ssh_part"
    log_info "Expected HTTP (port 80) CIDRs: $http_part"
    
    local expected_ssh_sorted=$(echo "$ssh_part" | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
    local expected_http_sorted=$(echo "$http_part" | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
    
    local next_token=""
    local page=1
    
    while true; do
        log_info "Fetching security groups page $page..."
        
        local query_result
        if [ -z "$next_token" ]; then
            query_result=$(aws ec2 describe-security-groups \
                --region "$region" \
                --max-items 50 \
                --output json 2>&1)
        else
            query_result=$(aws ec2 describe-security-groups \
                --region "$region" \
                --max-items 50 \
                --starting-token "$next_token" \
                --output json 2>&1)
        fi
        
        if [ $? -ne 0 ]; then
            error_exit "Failed to describe security groups. AWS CLI error: $query_result"
        fi
        
        # Extract security group IDs
        local sg_ids=$(echo "$query_result" | jq -r '.SecurityGroups[].GroupId')
        next_token=$(echo "$query_result" | jq -r '.NextToken // empty')
        
        for sg_id in $sg_ids; do
            log_debug "Checking security group: $sg_id"
            
            local actual_ssh_rules=$(aws ec2 describe-security-groups \
                --region "$region" \
                --group-ids "$sg_id" \
                --query "SecurityGroups[0].IpPermissions[?FromPort==\`22\` && ToPort==\`22\`].IpRanges[*].CidrIp" \
                --output text 2>&1)
            
            if [ $? -ne 0 ]; then
                log_warn "Failed to get SSH rules for $sg_id"
                continue
            fi
            
            local actual_http_rules=$(aws ec2 describe-security-groups \
                --region "$region" \
                --group-ids "$sg_id" \
                --query "SecurityGroups[0].IpPermissions[?FromPort==\`80\` && ToPort==\`80\`].IpRanges[*].CidrIp" \
                --output text 2>&1)
            
            if [ $? -ne 0 ]; then
                log_warn "Failed to get HTTP rules for $sg_id"
                continue
            fi
            
            local actual_ssh_sorted=$(echo "$actual_ssh_rules" | tr '\t' ' ' | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
            local actual_http_sorted=$(echo "$actual_http_rules" | tr '\t' ' ' | tr ' ' '\n' | sort | tr '\n' ' ' | xargs)
            
            log_debug "SG $sg_id - SSH rules: $actual_ssh_sorted"
            log_debug "SG $sg_id - HTTP rules: $actual_http_sorted"
            
            if [[ "$expected_ssh_sorted" == "$actual_ssh_sorted" && "$expected_http_sorted" == "$actual_http_sorted" ]]; then
 
                log_info "Found matching security group: $sg_id"
                log_info "SSH (port 22) rules match: $actual_ssh_sorted"
                log_info "Current HTTP (port 80) rules: $actual_http_sorted"
                echo "$sg_id"
                return 0
            fi
        done
        
        # Check if there are more pages
        if [ -z "$next_token" ] || [ "$next_token" == "null" ]; then
            break
        fi
        
        ((page++))
    done
    
    error_exit "No security group found matching YAML SSH rules (port 22): $expected_ssh_sorted"
}

# Fetch Cloudflare IPv4 ranges
get_cloudflare_ips() {
    log_info "Fetching Cloudflare IPv4 ranges..."
    
    local cf_ips
    if ! cf_ips=$(curl -s -f --connect-timeout 10 https://www.cloudflare.com/ips-v4 2>&1); then
        error_exit "Failed to fetch Cloudflare IPs. Error: $cf_ips"
    fi
    
    if [ -z "$cf_ips" ]; then
        error_exit "Cloudflare IP list is empty"
    fi
   
    local ip_count
    ip_count=$(echo "$cf_ips" | wc -l)
    log_debug "Fetched $ip_count Cloudflare IP ranges"
    
    echo "$cf_ips"
}

# Parse YAML file
parse_yaml() {
    log_info "Parsing YAML file: $YAML_FILE"
    
    if [ ! -f "$YAML_FILE" ]; then
        log_warn "YAML file not found: $YAML_FILE - will be created after sync"
        # Create a default YAML if it doesn't exist
        cat > "$YAML_FILE" << EOF
name: security-group
rules:
  ssh:
    - 0.0.0.0/0
  http:
    - $MY_HOME_IP
EOF
        log_info "Created default YAML file"
    fi
    
    log_debug "YAML file exists and is readable"
}

# Sync security group rules
sync_security_group() {
    local region=$1
    local sg_id=$2
    local cloudflare_ips=$3
    
    log_info "Syncing security group: $sg_id in region: $region"
    
    local current_http_cidrs
    if ! current_http_cidrs=$(aws ec2 describe-security-groups \
        --region "$region" \
        --group-ids "$sg_id" \
        --query "SecurityGroups[0].IpPermissions[?FromPort==\`80\` && ToPort==\`80\`].IpRanges[*].CidrIp" \
        --output text 2>&1); then
        error_exit "Failed to get current HTTP rules. AWS CLI error: $current_http_cidrs"
    fi
    
    log_info "Current HTTP CIDRs: $current_http_cidrs"
    
    declare -A desired_cidrs
    desired_cidrs["$MY_HOME_IP"]=1
    
    while IFS= read -r cf_ip; do
        if [ -n "$cf_ip" ]; then
            desired_cidrs["$cf_ip"]=1
            log_debug "Added to desired list: $cf_ip"
        fi
    done <<< "$cloudflare_ips"
    
    log_info "Total desired HTTP rules: ${#desired_cidrs[@]}"
    
    for cidr in $current_http_cidrs; do
        if [ -z "${desired_cidrs[$cidr]}" ]; then
            log_warn "Removing stale HTTP rule: $cidr"
            if ! aws ec2 revoke-security-group-ingress \
                --region "$region" \
                --group-id "$sg_id" \
                --protocol tcp \
                --port 80 \
                --cidr "$cidr" 2>&1; then
                log_warn "Failed to remove $cidr (may already be removed)"
            fi
        else
            log_debug "Keeping existing rule: $cidr"
        fi
    done
   
    for cidr in "${!desired_cidrs[@]}"; do
        if ! echo "$current_http_cidrs" | grep -qw "$cidr"; then
            log_info "Adding HTTP rule: $cidr"
            if ! aws ec2 authorize-security-group-ingress \
                --region "$region" \
                --group-id "$sg_id" \
                --protocol tcp \
                --port 80 \
                --cidr "$cidr" 2>&1; then
                log_warn "Failed to add $cidr (may already exist)"
            fi
        else
            log_debug "Rule already exists: $cidr"
        fi
    done
    
    log_info "Security group sync completed"
}

# Update YAML file with current rules
update_yaml() {
    local region=$1
    local sg_id=$2
    
    log_info "Updating YAML file..."
    
    local ssh_cidrs
    if ! ssh_cidrs=$(aws ec2 describe-security-groups \
        --region "$region" \
        --group-ids "$sg_id" \
        --query "SecurityGroups[0].IpPermissions[?FromPort==\`22\` && ToPort==\`22\`].IpRanges[*].CidrIp" \
        --output text 2>&1); then
        log_error "Failed to get SSH rules for YAML update"
        return 1
    fi
    
    ssh_cidrs=$(echo "$ssh_cidrs" | tr '\t' '\n' | sort -u)
    
    local http_cidrs
    if ! http_cidrs=$(aws ec2 describe-security-groups \
        --region "$region" \
        --group-ids "$sg_id" \
        --query "SecurityGroups[0].IpPermissions[?FromPort==\`80\` && ToPort==\`80\`].IpRanges[*].CidrIp" \
        --output text 2>&1); then
        log_error "Failed to get HTTP rules for YAML update"
        return 1
    fi
    
    http_cidrs=$(echo "$http_cidrs" | tr '\t' '\n' | sort -u)
    
    # Create new YAML content
    cat > "$YAML_FILE" << EOF
name: security-group
rules:
  ssh:
EOF
    
    while IFS= read -r cidr; do
        [ -n "$cidr" ] && echo "    - $cidr" >> "$YAML_FILE"
    done <<< "$ssh_cidrs"
    
    echo "  http:" >> "$YAML_FILE"
    
    while IFS= read -r cidr; do
        [ -n "$cidr" ] && echo "    - $cidr" >> "$YAML_FILE"
    done <<< "$http_cidrs"
    
    log_info "YAML file updated successfully"
}

# Git operations
git_commit_and_push() {
    log_info "Committing and pushing changes to Git..."
    
    git config --global user.email "test2bcloud@gmail.com" 2>/dev/null || true
    git config --global user.name "Security Group Sync" 2>/dev/null || true
    
    if [ ! -d .git ]; then
        log_info "Initializing git repository..."
        git init
        git remote add origin "$GIT_REPO_URL" 2>/dev/null || true
        git fetch 2>&1 || log_warn "Fetch failed, continuing..."
        git checkout -b "$GIT_BRANCH" 2>/dev/null || git checkout "$GIT_BRANCH" 2>/dev/null || true
        git pull origin "$GIT_BRANCH" --rebase 2>&1 || log_warn "Pull failed, continuing..."
    fi
    
    git add "$YAML_FILE"
    
    if git diff --staged --quiet; then
        log_info "No changes to commit"
    else
        local commit_msg="Update security group rules - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        git commit -m "$commit_msg"
        
        log_info "Pushing to remote repository..."
        if ! git push -u origin "$GIT_BRANCH" 2>&1; then
            log_error "Git push failed. Please check your credentials and repository URL"
            return 1
        fi
        
        log_info "Changes pushed to Git repository successfully"
    fi
}

# Main execution
main() {
    log_info "===== Starting Security Group Sync Script ===="
    log_info "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "" >&2
    
    log_info "Checking prerequisites."
    command -v aws >/dev/null 2>&1 || error_exit "AWS CLI not found. Please install it."
    command -v curl >/dev/null 2>&1 || error_exit "curl not found. Please install it."
    command -v git >/dev/null 2>&1 || error_exit "git not found. Please install it."
    command -v jq >/dev/null 2>&1 || error_exit "jq not found. Please install it (required for JSON parsing)."
    log_info "All prerequisites met"
    echo "" >&2
    
    log_info "Step 1: Retrieving EC2 metadata"
    TOKEN=$(get_metadata_token)
    echo "" >&2
    
    REGION=$(get_region "$TOKEN")
    log_info "Region: $REGION"
    echo "" >&2
    
    log_info "Step 2: Parsing YAML file"
    parse_yaml
    YAML_RULES=$(parse_yaml_rules)
    
    SSH_RULES=$(echo "$YAML_RULES" | cut -d'|' -f1 | cut -d':' -f2)
    HTTP_RULES=$(echo "$YAML_RULES" | cut -d'|' -f2 | cut -d':' -f2)
    log_info "YAML SSH rules (port 22): $SSH_RULES"
    log_info "YAML HTTP rules (port 80): $HTTP_RULES"
    echo "" >&2
    
    log_info "Step 3: Finding security group"
    SG_ID=$(find_security_group "$REGION" "$YAML_RULES")
    log_info "Security Group ID: $SG_ID"
    echo "" >&2
    
    log_info "Step 4: Fetching Cloudflare IP ranges"
    CF_IPS=$(get_cloudflare_ips)
    log_info "Cloudflare IP count: $(echo "$CF_IPS" | wc -l)"
    echo "" >&2
    
    log_info "Step 5: Syncing security group rules"
    sync_security_group "$REGION" "$SG_ID" "$CF_IPS"
    echo "" >&2
    
    log_info "Step 6: Updating YAML file"
    update_yaml "$REGION" "$SG_ID"
    echo "" >&2
    
    log_info "Step 7: Committing to Git"
    git_commit_and_push
    echo "" >&2
    
    log_info "===== Script Completed Successfully! ====="
    log_info "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

trap 'log_error "Script failed at line $LINENO"' ERR

main "$@"
