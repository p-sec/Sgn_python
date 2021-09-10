class A():
    def __init__(self) -> None:
        pass
    def Ahello(self):
        return self.name

class B(A):
    def __init__(self) -> None:
        self.name = 2
        self.age = 3
    
    def Bhello(self):
        return self.name


#主要测试父类共享子类的初始话对象
bb =  B()
print(bb.Ahello())
print(bb.Bhello())