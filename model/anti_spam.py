import random
from typing import Dict, List, Pattern

import falcon
import passlib.hash
import regex


class Question:
    def __init__(self, cfg: Dict[str, str]):
        self.question: str = cfg['question']
        self.answer: Pattern = regex.compile(cfg['answer'], flags=regex.UNICODE)
        self.token: str = passlib.hash.hex_md5.hash(cfg['question'])

    def verify(self, answer: str):
        return self.answer.fullmatch(answer) is not None


class AntiSpam:
    auth = {
        'auth_disabled': True
    }

    def __init__(self, config: dict):
        self.questions: List[Question] = []
        self.question_by_token: Dict[str, Question] = dict()
        for question_cfg in config['questions']:
            question = Question(question_cfg)
            self.questions.append(question)
            self.question_by_token[question.token] = question

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        idx = random.randrange(0, len(self.questions))
        question = self.questions[idx]

        resp.status = falcon.HTTP_200
        resp.media = {'token': question.token, 'question': question.question}

    def verify_answer(self, container: Dict[str, str], token_key: str, answer_key: str):
        question = self.question_by_token.get(container.get(token_key))
        if question is None:
            raise falcon.HTTPForbidden(description="Invalid token")
        if not question.verify(container.get(answer_key)):
            raise falcon.HTTPForbidden(description="Wrong answer")

    def register(self, app: falcon.API):
        app.add_route('/anti-spam/', self)
