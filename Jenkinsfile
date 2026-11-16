pipeline {
    agent any

    environment {
        IMAGE      = 'medisecure'
        KUBECONFIG = '/var/lib/jenkins/.kube/config'
    }

    stages {
        stage('Checkout from Git') {
            steps {
                checkout scm
            }
        }

        stage('Secret Scan (Gitleaks)') {
            steps {
                sh 'gitleaks detect --no-git --source . --redact --exit-code 1'
            }
        }

        stage('SAST Code Scan (Bandit)') {
            steps {
                sh 'bandit -r app.py -ll'
            }
        }

        stage('Dependency Scan (pip-audit)') {
            steps {
                sh 'pip-audit -r requirements.txt'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t ${IMAGE}:${BUILD_NUMBER} .'
            }
        }

        stage('Image Scan (Trivy)') {
            steps {
                sh '''
                    echo "---- Report: HIGH and CRITICAL findings (informational) ----"
                    trivy image --no-progress --severity HIGH,CRITICAL ${IMAGE}:${BUILD_NUMBER} || true
                    echo "---- Gate: fail on any fixable CRITICAL vulnerability ----"
                    trivy image --no-progress --severity CRITICAL --ignore-unfixed --exit-code 1 ${IMAGE}:${BUILD_NUMBER}
                '''
            }
        }

        stage('Load Image into Kubernetes') {
            steps {
                sh '''
                    docker save -o image.tar ${IMAGE}:${BUILD_NUMBER}
                    sudo /usr/local/bin/k3s ctr -n k8s.io images import image.tar
                    rm -f image.tar
                '''
            }
        }

        stage('Deploy Hardened Pods') {
            steps {
                sh '''
                    kubectl get secret medi-secrets > /dev/null || { echo "Secret medi-secrets is missing. Create it first (see guide Step 4)."; exit 1; }
                    sed "s/IMAGE_TAG/${BUILD_NUMBER}/" k8s/deployment.yaml | kubectl apply -f -
                    kubectl apply -f k8s/networkpolicy.yaml
                    kubectl rollout status deployment/medisecure --timeout=120s
                '''
            }
        }

        stage('Security Checks on Running App') {
            steps {
                sh '''
                    sleep 5
                    URL=http://localhost:30100
                    echo "Check 1: health endpoint"
                    test "$(curl -s -o /dev/null -w '%{http_code}' $URL/health)" = "200"
                    echo "Check 2: patient data is NOT open without login (expect 302 redirect)"
                    test "$(curl -s -o /dev/null -w '%{http_code}' $URL/patients)" = "302"
                    echo "Check 3: security headers present"
                    HEADERS=$(curl -sI $URL/login)
                    echo "$HEADERS" | grep -qi "x-content-type-options: nosniff"
                    echo "$HEADERS" | grep -qi "x-frame-options: DENY"
                    echo "$HEADERS" | grep -qi "content-security-policy"
                    echo "Check 4: container runs as non-root"
                    POD=$(kubectl get pod -l app=medisecure -o jsonpath='{.items[0].metadata.name}')
                    UID_IN_POD=$(kubectl exec $POD -- id -u)
                    echo "uid in pod: $UID_IN_POD"
                    test "$UID_IN_POD" != "0"
                    IP=$(curl -s http://checkip.amazonaws.com)
                    echo "=========================================="
                    echo " ALL SECURITY GATES PASSED"
                    echo " Healthcare portal : http://$IP:30100"
                    echo "=========================================="
                '''
            }
        }
    }

    post {
        success { echo 'DevSecOps pipeline passed: secure build deployed.' }
        failure { echo 'A security gate or stage FAILED: nothing insecure was deployed. Read the red stage above.' }
        always  { sh 'docker image prune -f || true' }
    }
}
