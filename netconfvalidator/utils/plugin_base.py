#!/usr/bin/env python3

from typing import Set, Dict, Any, List, Union
from abc import ABC, abstractmethod
from networkx import MultiGraph, MultiDiGraph

# For additional warnings/information to pass to the user. Printed and ignored by main code.
class TestNotice(ABC):
    @abstractmethod
    def print(self) -> None:
        pass

# Can be either thrown or returned in a list. One test results in exactly one TestResult, which must be last in the returned list.
class TestResult(ABC):
    @abstractmethod
    def print(self):
        pass

class TestSuccess(TestResult):
    def __init__(self, message) -> None:
        self.__message = message

    def print(self):
        print("SUCCESS: " + self.__message)
    
class TestFailure(TestResult):
    def __init__(self, message) -> None:
        self.__message = message

    def print(self):
        print("FAILURE: " + self.__message)
    

class TestPluginBase(ABC):
    # Class must be able to be instantiated without arguments

    # Override this method to register tests
    def test_set(self) -> Set[str]:
        return set()
    
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def run_one_test(self, test_name:str, net_graph:MultiGraph, config_files:Dict[str, Dict[str, Any]], interfaces:Dict[str, List[str]], clients:Dict[str, Any]) -> List[Union[TestNotice, TestResult]]:
        pass
    