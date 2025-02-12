from tkinter import *

class STROT:
    def __init__(self) -> None:

        self.root = Tk()
        self.root.config(background="black")
        self.root.title("STROT")
        self.root.geometry("2000x1000+500+500")
        self.interface()
        self.root.mainloop()

    def interface(self) -> None:
        Label(self.root, text="S T R O T - GUI", font=("Courier New", 40), foreground="#ffffff", background="black").pack(pady=2)
        Label(self.root, text="Stealthy Tool for Root Oriented Tunneling", font=("Courier New", 20), foreground="#ffffff", background="black").pack()
        
        Label(self.root, text="Machine IP: 192.168.202.211", font=("", 25)).pack(pady=50)
        Label(self.root, text="Scanning the network ...", font=("", 20), foreground="#ffffff", background="black").pack()

        

if __name__ == "__main__":
    STROT()
