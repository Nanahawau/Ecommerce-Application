pipeline {
    agent any
    triggers {
        pollSCM '* * * * *'
    }
    stages {
        stage('Build') {
            steps {
                sh './mvnw -Dmaven.test.failure.ignore=true clean package'
            }
        }
//         stage('Test') {
//             steps {
//                 sh './mvnw test'
//             }
        }
}

