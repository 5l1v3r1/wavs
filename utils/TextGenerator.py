from util_functions import warning

# text generation module
try:
    from textgenrnn import textgenrnn
except ImportError:
    warning('Text generation relies on textgenrnn module, which wasnt found.')
    warning('Use "pip3 install textgenrnn"')
    exit()


class TextGenerator:
    def __init__(self, main):
        self.main = main
        self.textgen = textgenrnn()

    def _train_on_text(self, text_list):
        epochs_to_train = self.main.options['text_gen_epochs']
        try:
            self.textgen.train_on_texts(text_list, num_epochs=epochs_to_train)
        except:
            pass

    def generate(self, text_list):
        self._train_on_text(text_list)

        generated_list = []
        temperature = self.main.options['text_generator_temp']
        try:
            generated_list = self.textgen.generate(n=10,
                                                   temperature=temperature,
                                                   return_as_list=True)
        except:
            pass

        return generated_list
