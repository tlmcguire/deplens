class PALChain:
    def execute(self, code):
        exec(code)

vulnerable_chain = PALChain()
vulnerable_chain.execute("__import__('os').system('ls')")