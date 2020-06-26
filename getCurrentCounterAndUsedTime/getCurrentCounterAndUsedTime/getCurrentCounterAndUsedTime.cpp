// getCurrentCounterAndUsedTime.cpp : Este arquivo contém a função 'main'. A execução do programa começa e termina ali.
//

#include "pch.h"
#include <iostream>
#include <ctime>
#include <chrono>

int main()
{
    
	
	//std::time_t current = std::time(nullptr);
	using namespace std::chrono; // just to shorten the namespacing

	std::chrono::milliseconds now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
	std::chrono::milliseconds inicio(1512151500000);
	std::chrono::milliseconds millisecondsSinceBeginning = now - inicio;
	std::chrono::milliseconds millisecondsToStepBy(30 * 1000);

	uint64_t timer = (uint64_t)(floor(millisecondsSinceBeginning / millisecondsToStepBy));
	std::cout << std::chrono::milliseconds(now).count() << "\n";
	std::cout << std::chrono::milliseconds(millisecondsSinceBeginning).count() << "\n";
	
	// Little Endian Shift
	unsigned char data[8];
	data[0] = (unsigned char)(timer >> 56);
	data[1] = (unsigned char)(timer >> 48);
	data[2] = (unsigned char)(timer >> 40);
	data[3] = (unsigned char)(timer >> 32);
	data[4] = (unsigned char)(timer >> 24);
	data[5] = (unsigned char)(timer >> 16);
	data[6] = (unsigned char)(timer >> 8);
	data[7] = (unsigned char)(timer);

	std::cout << "Fim!\n";
}

// Executar programa: Ctrl + F5 ou Menu Depurar > Iniciar Sem Depuração
// Depurar programa: F5 ou menu Depurar > Iniciar Depuração

// Dicas para Começar: 
//   1. Use a janela do Gerenciador de Soluções para adicionar/gerenciar arquivos
//   2. Use a janela do Team Explorer para conectar-se ao controle do código-fonte
//   3. Use a janela de Saída para ver mensagens de saída do build e outras mensagens
//   4. Use a janela Lista de Erros para exibir erros
//   5. Ir Para o Projeto > Adicionar Novo Item para criar novos arquivos de código, ou Projeto > Adicionar Item Existente para adicionar arquivos de código existentes ao projeto
//   6. No futuro, para abrir este projeto novamente, vá para Arquivo > Abrir > Projeto e selecione o arquivo. sln
