import asyncio
import random
import time
from typing import List
import httpx

class TestClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.client = httpx.AsyncClient()
        
    async def create_sample_users(self, count: int = 10):
        """Create sample users"""
        users = []
        for i in range(count):
            user_data = {
                "name": f"User{i}",
                "email": f"user{i}@example.com",
                "age": random.randint(18, 65)
            }
            try:
                response = await self.client.post(f"{self.base_url}/users", json=user_data)
                if response.status_code == 200:
                    users.append(response.json())
                    print(f"✅ Created user: {user_data['name']}")
            except Exception as e:
                print(f"❌ Error creating user: {e}")
        
        return users
    
    async def generate_normal_traffic(self, duration: int = 60):
        """Generate normal API traffic"""
        print(f"🔄 Generating normal traffic for {duration} seconds...")
        
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                # Random operations
                operation = random.choice(['get_users', 'get_user', 'root'])
                
                if operation == 'get_users':
                    await self.client.get(f"{self.base_url}/users")
                elif operation == 'get_user':
                    user_id = random.randint(1, 10)
                    await self.client.get(f"{self.base_url}/users/{user_id}")
                else:
                    await self.client.get(f"{self.base_url}/")
                
                # Random delay
                await asyncio.sleep(random.uniform(0.1, 2.0))
                
            except Exception as e:
                print(f"❌ Error in normal traffic: {e}")
    
    async def generate_anomalous_traffic(self):
        """Generate anomalous traffic patterns"""
        print("🚨 Generating anomalous traffic...")
        
        # Rapid requests (potential DDoS)
        print("   - Generating rapid requests...")
        for _ in range(50):
            try:
                await self.client.get(f"{self.base_url}/users")
                await asyncio.sleep(0.01)  # Very short delay
            except:
                pass
        
        # Error generation
        print("   - Triggering errors...")
        for _ in range(5):
            try:
                await self.client.get(f"{self.base_url}/simulate-error")
            except:
                pass
        
        # Heavy load simulation
        print("   - Simulating heavy load...")
        for _ in range(3):
            try:
                await self.client.get(f"{self.base_url}/simulate-heavy-load")
            except:
                pass
        
        # Invalid requests
        print("   - Making invalid requests...")
        for _ in range(10):
            try:
                await self.client.get(f"{self.base_url}/users/{random.randint(1000, 9999)}")
            except:
                pass
    
    async def run_test_scenario(self):
        """Run a complete test scenario"""
        try:
            print("🧪 Starting test scenario...")
            
            # Create sample users
            await self.create_sample_users(10)
            
            # Generate normal traffic
            await self.generate_normal_traffic(30)
            
            # Generate anomalous traffic
            await self.generate_anomalous_traffic()
            
            # More normal traffic
            await self.generate_normal_traffic(30)
            
            print("✅ Test scenario completed!")
            
        finally:
            await self.client.aclose()

if __name__ == "__main__":
    client = TestClient()
    asyncio.run(client.run_test_scenario())
