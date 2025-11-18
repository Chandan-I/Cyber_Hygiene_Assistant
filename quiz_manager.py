import os, json, random, sys

def resource_path(relative_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

class QuizManager:
    def __init__(self, filename="quiz.json"):
        self.filename = resource_path(filename)
        self.questions = []
        self.remaining = []
        self.score = 0
        self.attempts = 0
        self._load()

    def _load(self):
        try:
            with open(self.filename, "r", encoding="utf-8") as f:
                self.questions = json.load(f)
            self.remaining = self.questions.copy()
        except Exception as e:
            print(f"[QuizManager] ERROR: {e}")
            self.questions, self.remaining = [], []

    def reset(self):
        self.score = 0
        self.attempts = 0
        self.remaining = self.questions.copy()

    def get_random_question(self):
        if not self.questions:
            raise ValueError("No questions loaded. Check quiz.json!")
        if not self.remaining:
            self.remaining = self.questions.copy()
        q = random.choice(self.remaining)
        self.remaining.remove(q)
        return q