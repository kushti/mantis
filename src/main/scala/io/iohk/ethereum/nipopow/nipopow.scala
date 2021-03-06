package io.iohk.ethereum.nipopow

import java.io.FileWriter
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}

import akka.util.ByteString
import io.iohk.ethereum.blockchain.sync.SyncController
import io.iohk.ethereum.crypto.{kec256, kec512, keyPairFromPrvKey}
import io.iohk.ethereum.db.storage.AppStateStorage
import io.iohk.ethereum.domain._
import io.iohk.ethereum.network.p2p.messages.PV62.BlockHeaderImplicits.BlockHeaderEnc
import io.iohk.ethereum.network.{PeerManagerActor, ServerActor}
import io.iohk.ethereum.nipopow.Nipopow.buildVector
import io.iohk.ethereum.nodebuilder.Node
import io.iohk.ethereum.transactions.PendingTransactionsManager.AddTransactions
import io.iohk.ethereum.utils.Logger
import org.spongycastle.crypto.AsymmetricCipherKeyPair
import org.spongycastle.crypto.params.ECPublicKeyParameters
import org.spongycastle.util.encoders.Hex

import scala.concurrent.Await
import scala.util.{Failure, Success, Try}


/**
  * Functions to construct and work with an interlink vector and NIPoPoW proofs.
  * See the paper https://eprint.iacr.org/2017/963.pdf for details.
  */
object Nipopow extends Logger {

  /**
    * Class to store information about superchain
    *
    * @param level - level of the superchain
    * @param blocks - blocks of the superchain
    */
  case class Level(level: Int, blocks: Seq[(Height, BlockHeader)]) {
    lazy val numBlocks: Int = blocks.size

    def withBlock(height: Height, block: BlockHeader): Level =
      this.copy(level = level, (height -> block) +: blocks)

    def lastId: ByteString = blocks.head._2.hash
  }
  
  type InterlinkVector = Map[Int, Level]
  type Height = BigInt

  def constructInnerchain(startHeight: Height, boundary: Height, level: Level): Level = {
    val newBlocks = level.blocks.filter(t => t._1 > boundary && t._1 < startHeight)
    Level(level.level, newBlocks)
  }

  def numberOfBlocks(iv: InterlinkVector): Int = iv.values.map(_.numBlocks).sum

  def numberOfUniqueBlocks(iv: InterlinkVector): Int = iv.values.toSeq.flatMap(_.blocks).map(_._1).toSet.size

  def calculatePoWValue(blockHeader: BlockHeader): ByteString = {
    val nonceReverted = blockHeader.nonce.reverse
    val hashBlockWithoutNonce = kec256(BlockHeader.getEncodedWithoutNonce(blockHeader))
    val seedHash = kec512(hashBlockWithoutNonce ++ nonceReverted)

    ByteString(kec256(seedHash ++ blockHeader.mixHash))
  }

  private def levels(blockHeader: BlockHeader): Seq[Int] = (1 to 256).takeWhile {level => isLevel(blockHeader, level)}

  private def isLevel(blockHeader: BlockHeader, level: Int): Boolean = {
    val powBoundary = BigInt(2).pow(256) / blockHeader.difficulty / BigInt(2).pow(level)
    val powValue = BigInt(1, calculatePoWValue(blockHeader).toArray)
    powValue <= powBoundary
  }

  def updateInterlinkVector(vector: InterlinkVector, blockHeader: BlockHeader, height: BigInt): InterlinkVector =
    levels(blockHeader).foldLeft(vector) { case (v, levelNum) =>
      val level = v.get(levelNum)
        .map(_.withBlock(height, blockHeader))
        .getOrElse(Level(levelNum, Seq(height -> blockHeader)))
      v.updated(levelNum, level)
    }

  def prove(m: Int, k: Int, height: Height, vector: InterlinkVector): InterlinkVector = {
    val v = vector.filter(_._2.numBlocks >= m)
    val maxLevel = v.maxBy(_._1)._1
    maxLevel.to(1, -1).foldLeft((Map(): InterlinkVector, 1: Height)) { case ((iv, boundary), levelNum) =>
      val level = v(levelNum)
      val l = constructInnerchain(height - k, boundary, level)
      val newBoundary = level.blocks.drop(m - 1).head._1
      iv.updated(levelNum, l) -> newBoundary
    }._1
  }

  def dumpVectors(blockchain: Blockchain, bestBlock: BigInt): Unit = {
    var vector: InterlinkVector = Map()

    val fw = new FileWriter("/tmp/vector.txt", true)

    (1 to bestBlock.toInt).foreach { i =>
      val h = blockchain.getBlockHeaderByNumber(i).get

      val toDump =
      "=================\n" +
      "height: " + i + "\n" +
      vector.map(t => t._1 -> t._2.blocks.head._1).toSeq.sortBy(_._1) + "\n" +
      h.toString + "\n"

      fw.write(toDump)
      fw.flush()

      vector = updateInterlinkVector(vector, h, i)
    }
    fw.close()
  }

  def buildVector(blockchain: Blockchain, bestBlock: BigInt): ByteString = {
    var vector: InterlinkVector = Map()

    (1 to bestBlock.toInt).foreach { i =>
      val h = blockchain.getBlockHeaderByNumber(i).get
      vector = updateInterlinkVector(vector, h, i)
      if (vector.nonEmpty) log.trace("block#: " + i + " maxLevel: " + vector.maxBy(_._1))
    }

    //val maxLevel = vector.maxBy(_._1)._1

    val payload =
      vector(1).blocks.map{case (_, header) =>
        new BlockHeaderEnc(header).toBytes: ByteString
      }.reduce(_ ++ _)

    log.trace("bestBlock: " + bestBlock + " payload length: " + payload.length)
    val p = prove(m = 10, k = 6, bestBlock, vector)
    payload
  }
}

trait NipopowServer {self: Node =>
  def formTransaction(appStateStorage: AppStateStorage, fromKeyPair: AsymmetricCipherKeyPair): Try[SignedTransaction] = Try {
    val from = Address(kec256(fromKeyPair.getPublic.asInstanceOf[ECPublicKeyParameters].getQ.getEncoded(false).tail))
    val bestBlock = appStateStorage.getBestBlockNumber()
    val account = blockchain.getAccount(from, bestBlock).get
    val payloadBytes = buildVector(blockchain, bestBlock)

    val tx = new Transaction(
      nonce = account.nonce + 1,
      gasPrice = BigInt("34000000000"),
      gasLimit = 150000,
      receivingAddress = None,
      value = 1,
      payload = payloadBytes)
    SignedTransaction.sign(tx, fromKeyPair, None)
  }
}


object NipopowServerApp {

  def main(args: Array[String]): Unit = {

    //val privKey = Hex.decode(args.head)

    new Node with NipopowServer with Logger {

      def tryAndLogFailure(f: () => Any): Unit = Try(f()) match {
        case Failure(e) => log.warn("Error while shutting down...", e)
        case Success(_) =>
      }

      override def shutdown(): Unit = {
        tryAndLogFailure(() => Await.ready(actorSystem.terminate, shutdownTimeoutDuration))
        tryAndLogFailure(() => storagesInstance.dataSources.closeAll())
      }

      def start(): Unit = {
        //load genesis, if it is not loaded yet
        genesisDataLoader.loadGenesisData()

        peerManager ! PeerManagerActor.StartConnecting
        server ! ServerActor.StartServer(networkConfig.Server.listenAddress)
        syncController ! SyncController.StartSync

        if (jsonRpcHttpServerConfig.enabled) jsonRpcHttpServer.run()
      }

      start()

      val bestBlockNumber = storagesInstance.storages.appStateStorage.getBestBlockNumber()


      Nipopow.dumpVectors(blockchain, bestBlockNumber)

/*
      buildVector(blockchain, bestBlockNumber)

      val newAccountKeyPair: AsymmetricCipherKeyPair = keyPairFromPrvKey(privKey)

      val txTry = formTransaction(storagesInstance.storages.appStateStorage, newAccountKeyPair)

      println("stx: " + txTry)

      txTry.map { tx =>
        pendingTransactionsManager ! AddTransactions(tx)
      } */
    }
  }
}
