import subprocess
import json
import os


class AttackEngine:
    def __init__(self, exploit_lookup_path: str = "exploit_lookup_path") -> None:
        if not os.path.exists(exploit_lookup_path):
            raise FileNotFoundError("exploit_lookup_path file not found")

        self.exploit_lookup_path = exploit_lookup_path

        pass

    def exploit(self, exploit_path: str) -> None:
        return None

    def feedback(self) -> None:
        return

    @staticmethod
    def exploit_search(query: str) -> dict:
        """
        Searches for exploits related to a given query using searchsploit.

        Args:
            query (str): The search term for exploits.

        Returns:
            dict: JSON output of the search results or an error message.
        """
        if not len(query.strip()):
            return {
                "status": "error",
                "message": "No arguments to search exploit"
            }
        else:
            query = query + " remote py"
        try:
            print(f"Searching for exploits related to: {query}...")
            result_ = subprocess.run(["searchsploit", query, "--json"], capture_output=True, text=True, timeout=30)

            if result_.returncode == 0:
                return {
                    "status": "success",
                    "data": json.loads(result_.stdout)
                }
            else:
                return {
                    "status": "error",
                    "message": "Failed to retrieve exploits."
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


if __name__ == "__main__":
    ate = AttackEngine()
    # result = ate.exploit_search("ftp vsftpd")
    result = ate.exploit_search("ftp vsftpd")
    if result['status'] == "success":
        print("\nExploit Search Results:")
        print(json.dumps(result['data'], indent=4))
    else:
        print(f"Error: {result['message']}")
