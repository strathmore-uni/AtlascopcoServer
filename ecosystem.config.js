module.exports = {
    apps: [
      {
        name: 'server', // Change to your application name
        script: 'index.js', // Path to your main application file
        watch: true, // Enable auto-restart on file changes
        env: {
          NODE_ENV: 'production', // Set your environment
          API_URL: 'http://156.0.233.52/api', // Set your API URL
          PORT: 3000, // Set your application port
        },
      },
    ],
  };
  